require 'sinatra'
require 'sinatra/cookies'
require 'json'
require 'base64'
require 'date'
require 'net/http'
require 'securerandom'
require 'multi_json'

configure do
  set :bind, '0.0.0.0'
  set :port, '4567'
end

enable :sessions

requiredInfo = [ "email", "name" ]

knownUserKeys = Array.new

$knownIdentities = {}
$passwords = {}
$codes = {}
$nonces = {}

#Self EGO - for GNS
ego = '87DYZCD8DV2ENR8RC2S425FZPB93CV56XHG4DAQVVZ93RCWES6M0'
ego_name = 'example-rp'

#{"authorization_code" => ["AAT", "client_id"]}
$aat = {}

#list of valid Authorization API Access Tokens
valid_aat = ["valid_aat_1"]

#list of valid protection API Access Tokens
valid_pat = ["valid_pat_1"]

#{"permission_ticket" => ["resource_id",["scope_action1", "scope_action2", ...]]}
permission_reg = {"7d282e1b-28b3-4ecf-979f-2969078daf57"=>["112210f47de98100", ["view", "http://photoz.example.com/dev/actions/print"]]}

#requesting party token
#{"rpt" => "permission_ticket"}
rpt_scope = {}

# ticket => client_redirect_uri
claims_redirect_uris = {"7d282e1b-28b3-4ecf-979f-2969078daf57" => "http://client.example.com"}


#ticket => JWT containing credentials (from GNS)
gathered_claims = {}


#Sample policy
#For resource_set_id 123 and read permission
#Ego: IssuerUniversity - KNKSSJW5X9ERZ9AJ88D202WPFEGCZFJ2X8E5R90C8DNXDQXPQ8YG
policy = {name: '123_read', value: ['KNKSSJW5X9ERZ9AJ88D202WPFEGCZFJ2X8E5R90C8DNXDQXPQ8YG.student']}

$knownClients = {'random_client_id' => 'lksajr327048olkxjf075342jldsau0958lkjds'}


def get_policy
  #TODO: Implement a REST call to GNS to get the policy
  return policy 
end

# policy_hash -> {name: '123_read', value: ['XW0HP8SEQZ4SQGEH3PSHBB9E0TKDCQC6DNCX9QAYS0K5XXHBJJ20.student']}
#permission_value -> [resource_id, [scopes]]
def resolve_policy(permission_value)
  policy = get_policy(permission_value)
  check_nil(policy,"Invalid scopes")
  resource_id,action = policy["name"].split('_')
  policy_hash = {}
  policy["value"].each do |condition|
    issuer = condition.split('.')[0]
    policy_hash[issuer] = condition.split('.')[1]
  end
end


def issue_attrs

end


def json(content)
    MultiJson.dump(content, pretty: true)
end

def decode_json(content)
    MultiJson.load(content, symbolize_keys: true)
end








def check_nil(var,error)
  if var.nil? 

    status 400
    content_type :json 
    {:error => error}.to_json
  end
end



def validate_bearer_token(env,token_array)
  bearer = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)

  #check if PAT is valid
  valid = false
  if bearer.nil?
    return false
  end

  token_array.each do |at| 
    if at == bearer
      valid = true
      break
    end
  end

  return valid 


end




def exchange_code_for_token(id_ticket, expected_nonce)
  p "Expected nonce: "+expected_nonce.to_s
  resp = `curl -X POST 'http://local.gnu:7776/idp/token?ticket=#{id_ticket}&expected_nonce=#{expected_nonce}'`
  p resp
  json = JSON.parse(resp)
  p json
  return nil if json.nil? or json.empty?
  token = json["token"]
  return nil if token.nil?
  header_b64 = token.split(".")[0]
  payload_b64 = token.split(".")[1]
  signature = token.split(".")[2]
  plain = Base64.decode64(payload_b64)
  payload = JSON.parse(plain)
  return nil unless expected_nonce == payload["nonce"].to_i
  identity = payload["iss"]
  p payload
  $knownIdentities[identity] = payload
  $codes[identity] = id_ticket
  return identity
end

def is_token_expired (token)
  return true if token.nil?
  identity = $knownIdentities[token["iss"]]
  exp = Time.at(token["exp"] / 1000000)
  if (Time.now > exp)
    # Get new token
    new_token = `gnunet-gns -u #{$codes[identity]}.gnu -p #{token["iss"]} -t ID_TOKEN --raw -T 5000`
    if (new_token.nil? or new_token.empty?)
      $knownIdentities[token["iss"]] = nil
      return true
    end
    new_token = JSON.parse(new_token)
    exp = Time.at(new_token["exp"] / 1000000)
    if (Time.now > exp)
      $knownIdentities[token["iss"]] = nil
      return true
    else
      $knownIdentities[token["iss"]] = new_token
      return false
    end
  else
    # Check if token revoked
    return false
  end
end

get '/logout' do
  if (!session["user"].nil?)
    session["user"] = nil
    redirect to('/login')
  end
  return "Not logged in"
end

def getUser(identity)
  return nil if identity.nil? or $knownIdentities[identity].nil?
  return $knownIdentities[identity]["full_name"] unless $knownIdentities[identity]["full_name"].nil?
  return $knownIdentities[identity]["sub"]
end

get '/' do
  identity = session["user"]

  if (!identity.nil?)
    token = $knownIdentities[identity]
    #if (is_token_expired (token))
    #  # Token is expired
    #  redirect "/login"
    #end
    if (!token.nil?)
      phone = token["phone"]
      #msg = "Welcome back #{$knownIdentities[identity]["sub"]}"
      #msg += "<br/> Your phone number is: #{phone}"
      exp = token["exp"] / 1000000
      #msg += "<br/>Your token will expire at: #{Time.at(exp).to_s}"
      return haml :info, :locals => {
        :user => getUser(identity),
        :title => "Userinfo",
        :subtitle => "Welcome back #{$knownIdentities[identity]["full_name"]}",
        :content => "Your <b>phone</b> number is: #{phone}<br/>Your token will <b>expire at</b>: #{Time.at(exp).to_s}.<br/>Used <b>ticket</b>: #{$codes[identity]}.<br/>Token: #{$knownIdentities[identity]}<br/>"}
      end
    end

    redirect "/login"
  end

  get "/login" do
    identity = session["user"]
    token = params[:id_token]
    id_ticket = params[:ticket]

  # Identity parameter takes precendence over cookie
  #if (!params[:identity].nil?)
  #  identity = params[:identity]
  #end

  p session
  if (!identity.nil?)
    token = $knownIdentities[identity]
    p token
    #if ($passwords[identity].nil?)
    #  # New user -> register
    #  redirect "/register?identity="+identity
    #  return
    #end

    #if (is_token_expired (token))
      # Token is expired
    #  p "Token expired!"
    #end
    
    if (!token.nil?)
      redirect "/"
    end

  end

  if (!id_ticket.nil?)
    identity = exchange_code_for_token(id_ticket, $nonces[session["id"]])
    p "Deleting nonce"
    $nonces[session["id"]] = nil
    if (identity.nil?)
      return "Error!"
    end
    token = $knownIdentities[identity]
    p token
    phone = $knownIdentities[identity]["phone"]
    session["user"] = identity
    if (phone.nil?)
      return "You did not provide a valid phone attribute. Please grant us access to your phone number so we can call you in emergencies!<br/> <a href=http://localhost:8000/index.html#/identities/#{identity}?requested_by=http%3A//localhost%3A4567/&requested_attrs=phone>Grant access</a>"
    end
    #Handle token contents
    if session["redirect_uri_authorize"]
      redirect session["redirect_uri_authorize"]
    else
      redirect "/"
    end
  elsif (identity.nil?)
    nonce = rand(100000)
    session["id"] = rand(100000)
    $nonces[session["id"]] = nonce
    return haml :login, :locals => {
      :user => getUser(nil),
      :title => "Login",
      :nonce => nonce
    }
    #elsif (oauth_code.nil?)
    #  haml :grant, :locals => {:user => getUser(identity), :haml_id => identity, :title => "Information Needed"}
    #elsif (!identity.nil? and !grant_lbl.nil?)
    #  $knownIdentities[identity] = grant_lbl
  end
end

get '/authorize' do
  #Step #3
  identity = session["user"]
  client_id = params['client_id']
  redirect_uri = params['redirect_uri']
  scope = params['scope']
  session["redirect_uri_authorize"] = 'http://'+ env["HTTP_HOST"]+env["REQUEST_URI"]


  unless identity.nil?
    token = $knownIdentities[identity]
    unless token.nil?
        #Step #8
        #TODO: For later: Maybe add consent page
        #DONE: Build AAT and code
        #TODO: Associate AAT with client and user and CODE
        #(TODO: Check if client is known)
        
        #v4 UUID
        aat = SecureRandom.uuid

        authorization_code = SecureRandom.hex
        $aat[authorization_code] = [aat,client_id]
        valid_aat << aat

        redirect redirect_uri+"?code="+authorization_code

      end
    end


  #Step #4
  redirect "/login"

end

post '/token' do
  #Step #9
  #TODO: Give token to client, IF Authorization header matches client_id:secret and return AAT
  puts env
  if env['HTTP_AUTHORIZATION'] 
    auth_header = Base64.decode64(env['HTTP_AUTHORIZATION'].split(' ', 2).last || '').split(/:/, 2)
    puts "Authoriztion exists #{auth_header.inspect}"
  else
    halt 401
  end

  client_id = auth_header[0]  
  client_secret = auth_header[1]
  authorization_code = params['code']
  
  puts authorization_code
  puts "AAT code" + $aat[authorization_code].inspect
  puts $aat.inspect
  if $aat[authorization_code] && !$knownClients[client_id].nil? 
    {access_token: $aat[authorization_code][0],token_type:"bearer",expires_in:2592000,scope:"uma_authorization",uid:SecureRandom.uuid}.to_json
  else
    halt 401
  end


end

before '/resource_perm_reg' do
  request.body.rewind
  @request_payload = JSON.parse request.body.read
end

#Resource permission registration
post '/resource_perm_reg' do 

  #check if PAT is valid
  valid = validate_bearer_token(env,valid_pat)
  
  if valid 
    rsrc_id = @request_payload["resource_set_id"]
    scopes = @request_payload["scopes"]

    
    permission_ticket = SecureRandom.uuid
    permission_reg[permission_ticket] = [rsrc_id,scopes]

    puts permission_reg.inspect
    status 201
    content_type :json 
    {:ticket => permission_ticket}.to_json
    
  else
    halt 401
  end
end



before '/rpt' do
  request.body.rewind
  @request_payload = JSON.parse request.body.read
end

#RPT generation
post '/rpt' do
  valid = validate_bearer_token(env,valid_aat)
  if valid
    permission_ticket = @request_payload["ticket"]

    #Check if ticket exists 
    if permission_reg[permission_ticket]
      rsrc_id = permission_reg[permission_ticket][0]
      scopes = permission_reg[permission_ticket][1]
    else
      status 400
      content_type :json 
      {:error => "expired_ticket"}.to_json
      halt 400, json({error: "expired_ticket"})
    end


    if gathered_claims[permission_ticket].nil?
      status 403
      content_type :json
      halt 403, json({error: "need_info",
       error_details: {
           requesting_party_claims: {
             required_claims: [
              #Not being interpreted, so we can leave this commented for now
=begin
               {
                 "name": "email23423453ou453", #get from policy
                 "claim_type": "urn:gns:credential:1.0",
                 "claim_token_format": 
                 ["http://gnunet.org/specs/credential"],
                 "issuer": ["https://example.com/idp"] #Get  from policy
               }
=end
               ],
               redirect_user: true,
               ticket: permission_ticket
             }
             }})
        
    end

    #Issue an RPT connecting resource & scope to RPT via permission ticket
    rpt = SecureRandom.hex
    rpt_scope[rpt] = permission_ticket

    puts rpt_scope.inspect

    status 200
    content_type :json 
    {:rpt => rpt}.to_json
  else
    halt 401
  end
end


#RPT claims gathering endpoint
get '/rpt_claims' do 
  claims_redirect_uris = params[:claims_redirect_uri]
  valid = validate_bearer_token(env,valid_aat)
  if valid
    permission_ticket = params[:ticket]
    #Check if ticket exists 
    if permission_reg[permission_ticket]
      rsrc_id = permission_reg[permission_ticket][0]
      scopes = permission_reg[permission_ticket][1]
    else
      status 400
      content_type :json 
      {:error => "expired_ticket"}.to_json
    end

    session["user"]

    puts "rpt claims"

    redirect "gnuidentity://?redirect_uri=http%3A%2F%2Ftestservice.gnu%3A4567%2Fclaims_gathering_cb%3Fpermission_ticket%3D#{permission_ticket}\
&client_id=YFJMNXKCQX99KECSE5MNQ3P1PTJMGBRNSBDCPFXZA3MM0HKNHNFG&issue_type=ticket\
&requested_verified_attrs=user&nonce=1234"#include the attributes required from policy
    #TODO nonce should be a random integer 


  else
    halt 401
  end




end


#Claims gathering callback - once claims are gathered they are pushed here
get '/claims_gathering_cb' do
  token = params[:id_token]
  id_ticket = params[:ticket]
  permission_ticket = params[:permission_ticket]

 
  if (!id_ticket.nil?)
    jwt_token = exchange_code_for_token(id_ticket, 1234) #Change nonce here
    puts "JWT token"
    p jwt_token
    gathered_claims[permission_ticket] = jwt_token
    #verify policy here
    success = true
    if success 

      redirect claims_redirect_uris[permission_ticket] + "?authorization_state=claims_submitted"

    else
      gathered_claims[permission_ticket] = nil
      redirect claims_redirect_uris[permission_ticket] + "?authorization_state=not_authorized"
      
    end

  end


end







before '/rpt_status' do
  request.body.rewind
  @request_payload = JSON.parse request.body.read
end

#RPT introspection endpoint
post '/rpt_status' do 

  valid = validate_bearer_token(env,valid_pat)
  if valid
    rpt = @request_payload["rpt"]

    check_nil(rpt,"No RPT given")

    permission_ticket = rpt_scope[rpt]

    check_nil(permission_ticket, "No permission associated with RPT")
    check_nil(permission_reg[permission_ticket], "Permission expired")

    
    puts permission_reg.inspect
    resource_id = permission_reg[permission_ticket][0]
    scopes = permission_reg[permission_ticket][1]

    expiry = Time.now.to_i + 10*60 #EPOCH

    status 200
    content_type :json 

    {
      active: true,
    exp: expiry, #Time period of 10 minutes from now (OPTIONAL param - if not given, permission lasts forever)
    permissions: [
      {
        resource_set_id: resource_id,
        scopes: scopes,
        exp: expiry
      }
    ]
    }.to_json



  else
    halt 401
  end



end