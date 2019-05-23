
require 'pathname'
require 'puppet/file_system'
require 'puppet/network/http_pool'

Puppet::Functions.create_function(:hiera_vault) do

  begin
    require 'json'
  rescue LoadError => e
    raise Puppet::DataBinding::LookupError, "[hiera-vault] Must install json gem to use hiera-vault backend"
  end

  dispatch :lookup_key do
    param 'Variant[String, Numeric]', :key
    param 'Hash', :options
    param 'Puppet::LookupContext', :context
  end

  def lookup_key(key, options, context)

    if confine_keys = options['confine_to_keys']
      raise ArgumentError, '[hiera-vault] confine_to_keys must be an array' unless confine_keys.is_a?(Array)

      begin
        confine_keys = confine_keys.map { |r| Regexp.new(r) }
      rescue StandardError => e
        raise Puppet::DataBinding::LookupError, "[hiera-vault] creating regexp failed with: #{e}"
      end

      regex_key_match = Regexp.union(confine_keys)

      unless key[regex_key_match] == key
        context.explain { "[hiera-vault] Skipping hiera_vault backend because key '#{key}' does not match confine_to_keys" }
        context.not_found
      end
    end

    if strip_from_keys = options['strip_from_keys']
      raise ArgumentError, '[hiera-vault] strip_from_keys must be an array' unless strip_from_keys.is_a?(Array)

      strip_from_keys.each do |prefix|
        key = key.gsub(Regexp.new(prefix), '')
      end
    end

    if ENV['VAULT_TOKEN'] == 'IGNORE-VAULT'
      context.not_found
    end

    result = vault_get(key, options, context)

    if result.nil? and options['continue_if_not_found']
      context.not_found
    else
      return result
    end
  end

  VAULT_JSON_OPTIONS = {
    max_nesting:      false,
    create_additions: false,
    symbolize_names:  false,
  }

  def vault_get(key, options, context)

    if ! ['string','json',nil].include?(options['default_field_parse'])
      raise ArgumentError, "[hiera-vault] invalid value for default_field_parse: '#{options['default_field_parse']}', should be one of 'string','json'"
    end

    if ! ['ignore','only',nil].include?(options['default_field_behavior'])
      raise ArgumentError, "[hiera-vault] invalid value for default_field_behavior: '#{options['default_field_behavior']}', should be one of 'ignore','only'"
    end

    begin
      token = options.fetch('token', ENV['VAULT_TOKEN'])
      if token.nil? or token.empty?
        tokenfile = Pathname.new('~/.vault-token').expand_path
        if Puppet::FileSystem.exist? tokenfile
          token = Puppet::FileSystem.read tokenfile
        end
      end

      headers = {
        'User-Agent'    => 'puppetserver/hiera_vault',
        'Content-Type'  => 'application/json',
        'Accept'        => 'application/json',
      }
      unless token.nil?
        headers['X-Vault-Token'] = token
      end

      url = URI.parse(options.fetch('address', ENV['VAULT_ADDR']))
      connection = Puppet::Network::HttpPool.http_instance(url.host, url.port)

      context.explain { "[hiera-vault] Client configured to connect to #{url}" }
    rescue StandardError => e
      raise Puppet::DataBinding::LookupError, "[hiera-vault] Skipping backend. Configuration error: #{e}"
    end

    answer = nil

    generic = options['mounts']['generic'].dup
    generic ||= [ 'secret' ]

    v2 = options['kv_v2']

    # Only generic mounts supported so far
    generic.each do |mount|
      path = context.interpolate([mount, key].join('/'))
      context.explain { "[hiera-vault] Looking in path #{path}" }
      if v2
        path = path.split('/').reject(&:empty?).insert(1,'data').join('/')
      end

      begin
        result = connection.get("/v1/#{path}", headers, options)
      rescue StandardError => e
        context.explain { "[hiera-vault] Error reading secret #{path}: #{e}" }
      end

      if result.body
        begin
          data = JSON.parse(result.body, VAULT_JSON_OPTIONS)
        rescue JSON::ParserError => e
          context.explain { "[hiera-vault] Could not parse vault response as json: #{e}" }
        end
      end

      if data
        case result
        when Net::HTTPSuccess
          secret = data['data']
          if v2
            secret = secret['data']
          end
        else
          context.explain { "[hiera-vault] Could not connect to read secret: #{path} (#{data.fetch('errors', ['unknown error']).join("\n")})" }
        end
      end

      next if secret.nil?

      context.explain { "[hiera-vault] Read secret: #{key}" }
      if (options['default_field'] and ( ['ignore', nil].include?(options['default_field_behavior']) ||
         (secret.has_key?(options['default_field']) && secret.length == 1) ) )

        return nil if ! secret.has_key?(options['default_field'])

        new_answer = secret[options['default_field']]

        if options['default_field_parse'] == 'json'
          begin
            new_answer = JSON.parse(new_answer, :quirks_mode => true)
          rescue JSON::ParserError => e
            context.explain { "[hiera-vault] Could not parse string as json: #{e}" }
          end
        end

      else
        new_answer = secret
      end

      if ! new_answer.nil?
        answer = new_answer
        break
      end
    end

    return answer
  end
end
