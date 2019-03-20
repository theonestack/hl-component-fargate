CfhighlanderTemplate do
  Name 'Fargate'
  DependsOn 'vpc'
  ComponentVersion component_version
  Description "#{component_name} - #{component_version}"

  Parameters do
    ComponentParam 'EnvironmentName', 'dev', isGlobal: true
    ComponentParam 'EnvironmentType', 'development', allowedValues: ['development','production'], isGlobal: true

    ComponentParam 'VPCId', type: 'AWS::EC2::VPC::Id'
    ComponentParam 'EcsCluster'
    ComponentParam 'StackOctet', isGlobal: true

    unless defined? security_group
      ComponentParam 'SecurityGroupBackplane'
    end

    if defined? targetgroup
      ComponentParam 'LoadBalancer'
      ComponentParam 'TargetGroup'
      ComponentParam 'Listener'
      ComponentParam 'DnsDomain', isGlobal: true
    end

    ComponentParam 'DesiredCount', 1
    ComponentParam 'MinimumHealthyPercent', 100
    ComponentParam 'MaximumPercent', 200

    ComponentParam 'EnableScaling', 'false', allowedValues: ['true','false']

    ComponentParam "Subnets", '', type: 'CommaDelimitedList' if use_subnet_list
    maximum_availability_zones.times do |az|
      ComponentParam "SubnetCompute#{az}", ''
    end unless use_subnet_list

    #create component params for service image tag parameters
    task_definition.each do |task_def, task|
      if task.has_key?('tag_param')
        default_value = task.has_key?('tag_param_default') ? task['tag_param_default'] : 'latest'
        ComponentParam task['tag_param'], default_value
      end
    end if defined? task_definition

  end

end
