CloudFormation do

  export = external_parameters.fetch(:export_name, external_parameters[:component_name])

  Logs_LogGroup('LogGroup') {
    LogGroupName Ref('AWS::StackName')
    RetentionInDays "#{external_parameters[:log_retention]}"
  }

  Condition('IsScalingEnabled', FnEquals(Ref('EnableScaling'), 'true'))

  definitions, task_volumes, secrets, secrets_policy = Array.new(4){[]}

  task_definition = external_parameters.fetch(:task_definition, {})
  task_definition.each do |task_name, task|

    env_vars, mount_points, ports = Array.new(3){[]}

    name = task.has_key?('name') ? task['name'] : task_name

    image_repo = task.has_key?('repo') ? "#{task['repo']}/" : ''
    image_name = task.has_key?('image') ? task['image'] : task_name
    image_tag = task.has_key?('tag') ? "#{task['tag']}" : 'latest'
    image_tag = task.has_key?('tag_param') ? Ref("#{task['tag_param']}") : image_tag

    # create main definition
    task_def =  {
      Name: name,
      Image: FnJoin('',[ image_repo, image_name, ":", image_tag ]),
      LogConfiguration: {
        LogDriver: 'awslogs',
        Options: {
          'awslogs-group' => Ref("LogGroup"),
          "awslogs-region" => Ref("AWS::Region"),
          "awslogs-stream-prefix" => name
        }
      }
    }

    task_def.merge!({ MemoryReservation: task['memory'] }) if task.has_key?('memory')
    task_def.merge!({ Cpu: task['cpu'] }) if task.has_key?('cpu')
    task_def.merge!({ ReadonlyRootFilesystem: task['read_only_root']}) if task.has_key?('read_only_root')

    if !(task['env_vars'].nil?)
      task['env_vars'].each do |name,value|
        split_value = value.to_s.split(/\${|}/)
        if split_value.include? 'environment'
          fn_join = split_value.map { |x| x == 'environment' ? [ Ref('EnvironmentName'), '.', FnFindInMap('AccountId',Ref('AWS::AccountId'),'DnsDomain') ] : x }
          env_value = FnJoin('', fn_join.flatten)
        elsif value == 'cf_version'
          env_value = cf_version
        else
          env_value = value
        end
        env_vars << { Name: name, Value: env_value}
      end
    end

    task_def.merge!({Environment: env_vars }) if env_vars.any?

    # add links
    if task.key?('links')
      task['links'].each do |links|
      task_def.merge!({ Links: [ links ] })
      end
    end

    # add entrypoint
    if task.key?('entrypoint')
      task_def.merge!({ EntryPoint: task['entrypoint'] })
    end

    # By default Essential is true, switch to false if `not_essential: true`
    task_def.merge!({ Essential: false }) if task['not_essential']

    # add docker volumes
    if task.key?('mounts')
      task['mounts'].each do |mount|
        parts = mount.split(':')
        mount_points << { ContainerPath: parts[0], SourceVolume: parts[1], ReadOnly: (parts[2] == 'ro' ? true : false) }
      end
      task_def.merge!({MountPoints: mount_points })
    end

    # volumes from
    if task.key?('volumes_from')
      task['volumes_from'].each do |source_container|
      task_def.merge!({ VolumesFrom: [ SourceContainer: source_container ] })
      end
    end

    # add port
    if task.key?('ports')
      port_mapppings = []
      task['ports'].each do |port|
        port_array = port.to_s.split(":").map(&:to_i)
        mapping = {}
        mapping.merge!(ContainerPort: port_array[0])
        mapping.merge!(HostPort: port_array[1]) if port_array.length == 2
        port_mapppings << mapping
      end
      task_def.merge!({PortMappings: port_mapppings})
    end

    task_def.merge!({Command: task['command'] }) if task.key?('command')
    task_def.merge!({HealthCheck: task['healthcheck'] }) if task.key?('healthcheck')
    task_def.merge!({WorkingDirectory: task['working_dir'] }) if task.key?('working_dir')
    task_def.merge!({User: task['user'] }) if task.key?('user')

    if task.key?('secrets')
      
      if task['secrets'].key?('ssm')
        secrets.push *task['secrets']['ssm'].map {|k,v| { Name: k, ValueFrom: v.is_a?(String) && v.start_with?('/') ? FnSub("arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter#{v}") : v }}
        resources = task['secrets']['ssm'].map {|k,v| v.is_a?(String) && v.start_with?('/') ? FnSub("arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter#{v}") : v }
        secrets_policy.push iam_policy_allow('ssm-secrets','ssm:GetParameters', resources)
      end
      
      if task['secrets'].key?('secretsmanager')
        secrets.push *task['secrets']['secretsmanager'].map {|k,v| { Name: k, ValueFrom: v.is_a?(String) && v.start_with?('/') ? FnSub("arn:aws:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:#{v}") : v }}
        resources = task['secrets']['secretsmanager'].map {|k,v| v.is_a?(String) && v.start_with?('/') ? FnSub("arn:aws:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:#{v}-*") : v }
        secrets_policy.push iam_policy_allow('secretsmanager','secretsmanager:GetSecretValue', resources)
      end
      
      if secrets.any?
        task_def.merge!({Secrets: secrets})
      end
      
    end

    definitions << task_def

  end

  # add docker volumes
  volumes = external_parameters.fetch(:volumes, [])
    volumes.each do |volume|
      parts = volume.split(':')
      object = { Name: parts[0]}
      object.merge!({ Host: { SourcePath: parts[1] }}) if parts[1]
      task_volumes << object
    end

  policies = []
  iam_policies = external_parameters.fetch(:iam_policies, {})
  iam_policies.each do |name,policy|
    policies << iam_policy_allow(name,policy['action'],policy['resource'] || '*')
  end

  IAM_Role('TaskRole') do
    AssumeRolePolicyDocument ({
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: [ 'ecs-tasks.amazonaws.com' ] },
          Action: [ 'sts:AssumeRole' ]
        },
        {
          Effect: 'Allow',
          Principal: { Service: [ 'ssm.amazonaws.com' ] },
          Action: [ 'sts:AssumeRole' ]
        }
      ]
    })
    Path '/'
    Policies(policies)
  end

  IAM_Role('ExecutionRole') do
    AssumeRolePolicyDocument ({
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: [ 'ecs-tasks.amazonaws.com' ] },
          Action: [ 'sts:AssumeRole' ]
        }
      ]
    })
    Path '/'
    Policies( [
      PolicyName: "FargateExecutionPolicy",
      PolicyDocument:
        {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
              ],
              Resource: "*"
            }
          ]
        }
    ])
  end

  ECS_TaskDefinition('Task') do
    ContainerDefinitions definitions
    NetworkMode 'awsvpc'
    RequiresCompatibilities ['FARGATE']
    TaskRoleArn Ref('TaskRole')
    ExecutionRoleArn Ref('ExecutionRole')

    if external_parameters[:cpu]
      Cpu external_parameters[:cpu]
    end

    if external_parameters[:memory]
      Memory external_parameters[:memory]
    end

    if task_volumes.any?
      Volumes task_volumes
    end

  end

  service_loadbalancer = []
  targetgroup = external_parameters.fetch(:targetgroup, {})
  unless targetgroup.empty?

    if targetgroup.has_key?('rules')

      attributes = []

      targetgroup['attributes'].each do |key,value|
        attributes << { Key: key, Value: value }
      end if targetgroup.has_key?('attributes')

      tags = []
      tags << { Key: "Environment", Value: Ref("EnvironmentName") }
      tags << { Key: "EnvironmentType", Value: Ref("EnvironmentType") }

      targetgroup['tags'].each do |key,value|
        tags << { Key: key, Value: value }
      end if targetgroup.has_key?('tags')

      ElasticLoadBalancingV2_TargetGroup('TaskTargetGroup') do
        ## Required
        Port targetgroup['port']
        Protocol targetgroup['protocol'].upcase
        VpcId Ref('VPCId')
        ## Optional
        if targetgroup.has_key?('healthcheck')
          HealthCheckPort targetgroup['healthcheck']['port'] if targetgroup['healthcheck'].has_key?('port')
          HealthCheckProtocol targetgroup['healthcheck']['protocol'] if targetgroup['healthcheck'].has_key?('port')
          HealthCheckIntervalSeconds targetgroup['healthcheck']['interval'] if targetgroup['healthcheck'].has_key?('interval')
          HealthCheckTimeoutSeconds targetgroup['healthcheck']['timeout'] if targetgroup['healthcheck'].has_key?('timeout')
          HealthyThresholdCount targetgroup['healthcheck']['heathy_count'] if targetgroup['healthcheck'].has_key?('heathy_count')
          UnhealthyThresholdCount targetgroup['healthcheck']['unheathy_count'] if targetgroup['healthcheck'].has_key?('unheathy_count')
          HealthCheckPath targetgroup['healthcheck']['path'] if targetgroup['healthcheck'].has_key?('path')
          Matcher ({ HttpCode: targetgroup['healthcheck']['code'] }) if targetgroup['healthcheck'].has_key?('code')
        end

        TargetType targetgroup['type'] if targetgroup.has_key?('type')
        TargetGroupAttributes attributes if attributes.any?

        Tags tags if tags.any?
      end

      targetgroup['rules'].each_with_index do |rule, index|
        listener_conditions = []
        if rule.key?("path")
          listener_conditions << { Field: "path-pattern", Values: [ rule["path"] ] }
        end
        if rule.key?("host")
          hosts = []
          if rule["host"].include?('!DNSDomain')
            host_subdomain = rule["host"].gsub('!DNSDomain', '') #remove <DNSDomain>
            hosts << FnJoin("", [ host_subdomain , Ref('DnsDomain') ])
          elsif rule["host"].include?('.')
            hosts << rule["host"]
          else
            hosts << FnJoin("", [ rule["host"], ".", Ref('DnsDomain') ])
          end
          listener_conditions << { Field: "host-header", Values: hosts }
        end

        ElasticLoadBalancingV2_ListenerRule("TargetRule#{rule['priority']}") do
          Actions [{ Type: "forward", TargetGroupArn: Ref('TaskTargetGroup') }]
          Conditions listener_conditions
          ListenerArn Ref("Listener")
          Priority rule['priority'].to_i
        end

      end

      targetgroup_arn = Ref('TaskTargetGroup')

      Output("TaskTargetGroup") {
        Value(Ref('TaskTargetGroup'))
        Export FnSub("${EnvironmentName}-#{export}-targetgroup")
      }
    else
      targetgroup_arn = Ref('TargetGroup')
    end


    service_loadbalancer << {
      ContainerName: targetgroup['container'],
      ContainerPort: targetgroup['port'],
      TargetGroupArn: targetgroup_arn
    }

  end

  sg_name = 'SecurityGroupBackplane'
  security_group = external_parameters.fetch(:security_group, [])
  if security_group.any?
    EC2_SecurityGroup('ServiceSecurityGroup') do
      VpcId Ref('VPCId')
      GroupDescription "#{external_parameters[:component_name]} fargate service"
      SecurityGroupIngress sg_create_rules(security_group, ip_blocks)
    end
    sg_name = 'ServiceSecurityGroup'
  end

  task_ingress_rules = external_parameters.fetch(:task_ingress_rules, [])
  task_ingress_rules.each do |rule|

    EC2_SecurityGroupIngress(:AllowConnectionBetweenContainerAndLB) {
      Description 'Allow Connection Between Container And LB'
      GroupId Ref(:ServiceSecurityGroup)
      SourceSecurityGroupId Ref(:LoadbalancerSecurityGroup)
      IpProtocol 'tcp'
      FromPort rule['from_port']
      ToPort rule['to_port']
    }

  end

  health_check_grace_period = external_parameters.fetch(:health_check_grace_period, nil)
  unless task_definition.empty?
    ECS_Service('Service') do
      Cluster Ref("EcsCluster")
      DesiredCount Ref('DesiredCount')
      DeploymentConfiguration ({
          MinimumHealthyPercent: Ref('MinimumHealthyPercent'),
          MaximumPercent: Ref('MaximumPercent')
      })
      TaskDefinition Ref('Task')
      HealthCheckGracePeriodSeconds health_check_grace_period unless health_check_grace_period.nil?
      LaunchType "FARGATE"

      if service_loadbalancer.any?
        LoadBalancers service_loadbalancer
      end

      NetworkConfiguration ({
        AwsvpcConfiguration: {
          AssignPublicIp: external_parameters[:public_ip] ? "ENABLED" : "DISABLED",
          SecurityGroups: [ Ref(sg_name) ],
          Subnets: FnSplit(',', Ref('Subnets'))
        }
      })

    end

    Output('ServiceName') do
      Value(FnGetAtt('Service', 'Name'))
      Export FnSub("${EnvironmentName}-#{export}-ServiceName")
    end
  end

  scaling_policy = external_parameters.fetch(:scaling_policy, {})
  unless scaling_policy.empty?

    IAM_Role(:ServiceECSAutoScaleRole) {
      Condition 'IsScalingEnabled'
      AssumeRolePolicyDocument service_role_assume_policy('application-autoscaling')
      Path '/'
      Policies ([
        PolicyName: 'ecs-scaling',
        PolicyDocument: {
          Statement: [
            {
              Effect: "Allow",
              Action: ['cloudwatch:DescribeAlarms','cloudwatch:PutMetricAlarm','cloudwatch:DeleteAlarms'],
              Resource: "*"
            },
            {
              Effect: "Allow",
              Action: ['ecs:UpdateService','ecs:DescribeServices'],
              Resource: Ref('Service')
            }
          ]
      }])
    }

    ApplicationAutoScaling_ScalableTarget(:ServiceScalingTarget) {
      Condition 'IsScalingEnabled'
      MaxCapacity scaling_policy['max']
      MinCapacity scaling_policy['min']
      ResourceId FnJoin( '', [ "service/", Ref('EcsCluster'), "/", FnGetAtt(:Service,:Name) ] )
      RoleARN FnGetAtt(:ServiceECSAutoScaleRole,:Arn)
      ScalableDimension "ecs:service:DesiredCount"
      ServiceNamespace "ecs"
    }

    ApplicationAutoScaling_ScalingPolicy(:ServiceScalingUpPolicy) {
      Condition 'IsScalingEnabled'
      PolicyName FnJoin('-', [ Ref('EnvironmentName'), external_parameters[:component_name], "scale-up-policy" ])
      PolicyType "StepScaling"
      ScalingTargetId Ref(:ServiceScalingTarget)
      StepScalingPolicyConfiguration({
        AdjustmentType: "ChangeInCapacity",
        Cooldown: scaling_policy['up']['cooldown'] || 300,
        MetricAggregationType: "Average",
        StepAdjustments: [{ ScalingAdjustment: scaling_policy['up']['adjustment'].to_s, MetricIntervalLowerBound: 0 }]
      })
    }

    ApplicationAutoScaling_ScalingPolicy(:ServiceScalingDownPolicy) {
      Condition 'IsScalingEnabled'
      PolicyName FnJoin('-', [ Ref('EnvironmentName'), external_parameters[:component_name], "scale-down-policy" ])
      PolicyType 'StepScaling'
      ScalingTargetId Ref(:ServiceScalingTarget)
      StepScalingPolicyConfiguration({
        AdjustmentType: "ChangeInCapacity",
        Cooldown: scaling_policy['down']['cooldown'] || 900,
        MetricAggregationType: "Average",
        StepAdjustments: [{ ScalingAdjustment: scaling_policy['down']['adjustment'].to_s, MetricIntervalUpperBound: 0 }]
      })
    }

    default_alarm = {}
    default_alarm['metric_name'] = 'CPUUtilization'
    default_alarm['namespace'] = 'AWS/ECS'
    default_alarm['statistic'] = 'Average'
    default_alarm['period'] = '60'
    default_alarm['evaluation_periods'] = '5'
    default_alarm['dimensions'] = [
      { Name: 'ServiceName', Value: FnGetAtt(:Service,:Name)},
      { Name: 'ClusterName', Value: Ref('EcsCluster')}
    ]

    CloudWatch_Alarm(:ServiceScaleUpAlarm) {
      Condition 'IsScalingEnabled'
      AlarmDescription FnJoin(' ', [Ref('EnvironmentName'), "#{external_parameters[:component_name]} ecs scale up alarm"])
      MetricName scaling_policy['up']['metric_name'] || default_alarm['metric_name']
      Namespace scaling_policy['up']['namespace'] || default_alarm['namespace']
      Statistic scaling_policy['up']['statistic'] || default_alarm['statistic']
      Period (scaling_policy['up']['period'] || default_alarm['period']).to_s
      EvaluationPeriods scaling_policy['up']['evaluation_periods'].to_s
      Threshold scaling_policy['up']['threshold'].to_s
      AlarmActions [Ref(:ServiceScalingUpPolicy)]
      ComparisonOperator 'GreaterThanThreshold'
      Dimensions scaling_policy['up']['dimensions'] || default_alarm['dimensions']
      TreatMissingData scaling_policy['up']['missing_data'] if scaling_policy['up'].has_key?('missing_data')
    }

    CloudWatch_Alarm(:ServiceScaleDownAlarm) {
      Condition 'IsScalingEnabled'
      AlarmDescription FnJoin(' ', [Ref('EnvironmentName'), "#{external_parameters[:component_name]} ecs scale down alarm"])
      MetricName scaling_policy['down']['metric_name'] || default_alarm['metric_name']
      Namespace scaling_policy['down']['namespace'] || default_alarm['namespace']
      Statistic scaling_policy['down']['statistic'] || default_alarm['statistic']
      Period (scaling_policy['down']['period'] || default_alarm['period']).to_s
      EvaluationPeriods scaling_policy['down']['evaluation_periods'].to_s
      Threshold scaling_policy['down']['threshold'].to_s
      AlarmActions [Ref(:ServiceScalingDownPolicy)]
      ComparisonOperator 'LessThanThreshold'
      Dimensions scaling_policy['down']['dimensions'] || default_alarm['dimensions']
      TreatMissingData scaling_policy['down']['missing_data'] if scaling_policy['down'].has_key?('missing_data')
    }

  end
end