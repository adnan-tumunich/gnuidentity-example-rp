require 'sinatra'
require 'sinatra/cookies'
require 'json'
require 'base64'
require 'date'
require 'net/http'
require 'securerandom'
require 'multi_json'
require 'pp'

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

#Sample permission ticket hash
$perm_tkt_hash = {"7d282e1b-28b3-4ecf-979f-2969078daf57" => {
   "resource_owner_pkey" => "MFVZ0430PK23XJMBVBWG",
   "resource_set_id" => "123456",
   "scopes" => ["read"],
   "claims_redirect_uri" => "http://192.168.33.10",
   "req_ver_attr" => {"RWPKFRY7AKDBXJB1VNCSRJMT0.student" => "student_read_0"},
   "req_ver_attr_http" => "student_read_0",
   "claims_gathered" => {"RWPKFRY7AKDBXJB1VNCSRJMT0.student" => {},
   },
   "claims_array" => ["RWPKFRY7AKDBXJB1VNCSRJMT0.student"],
    "scopes_hash" => {
      "read" => {
        "policy_name" => "123456_read",
        "policy_sets" => [["RWPKFRY7AKDBXJB1VNCSRJMT0.student"]]
      }
      
   }    
  }
} 

#Self EGO - for GNS 
$ego = 'YFJMNXKCQX99KECS'
$ego_name = 'master-zone'

#{"authorization_code" => ["AAT", "client_id"]}
$aat = {}

#list of valid Authorization API Access Tokens
valid_aat = ["valid_aat_1"]

#list of valid protection API Access Tokens
valid_pat = ["valid_pat_1"]

#{"permission_ticket" => ["resource_id",["scope_action1", "scope_action2", ...]]}
permission_reg = {"7d282e1b-28b3-4ecf-979f-2969078daf57"=>["MFVZ0430P5CRHSYY8K23X45J06YYTXSJFG7PCTR608WZMJMBVBWG.18687878", ["read"]]}

#requesting party token
#{"rpt" => "permission_ticket"}
$rpt_scope = {"7ed619d1d1dc3ecaf7156a039519c653" => "49edb94f-4710-4c1e-a46b-147a34254a9e"}

$knownClients = {'random_client_id' => 'lksajr327048olkxjf075342jldsau0958lkjds'}

def check_nil(var,error)
  if var.nil? 

    status 400
    content_type :json 
    {:error => error}.to_json
  end
end

def check_empty(var,error)
  if var.empty?
    status 400
    content_type :json
    {:error => error}.to_json
  end
end

def get_policies(perm_tkt)
  curr_perm = $perm_tkt_hash[perm_tkt]
  pkey = curr_perm["resource_owner_pkey"]
  scopes = curr_perm["scopes"]
  curr_perm["claims_array"] = []
  curr_perm['claims_gathered'] = {}
  curr_perm["req_ver_attr"] = {}
  curr_perm["req_ver_attr_http"] = "" 
  curr_perm["scopes_hash"] = {}
  attr_count = 0 
  scopes.each do |scope|
    curr_perm["scopes_hash"][scope] = {}
    policy_name = ("#{curr_perm['resource_set_id']}_#{scope}")
    curr_perm["scopes_hash"][scope]["policy_name"] = policy_name
    get_policy_cmd =`gnunet-gns -u #{policy_name}.#{pkey}.zkey -t POLICY --raw`
    curr_perm["scopes_hash"][scope]["policy_sets"] = []
    policies = get_policy_cmd.split("\n")
    policies.each do |policy|
      policy_hash = JSON.parse(policy)
      curr_perm["scopes_hash"][scope]["policy_sets"].push(policy_hash["policy"])
      iss_attr_array = policy_hash["policy"]
      iss_attr_array.each do |iss_attr|
        curr_perm["claims_array"].push(iss_attr)
        issue_verified_attribute(iss_attr,scope,curr_perm,attr_count)
        attr_count +=1
        curr_perm['claims_gathered'][iss_attr] = {}
      end
    end
  end
  curr_perm['req_ver_attr_http'][-1] = ''
  pp $perm_tkt_hash
end

def gather_claims_request(perm_tkt)
  curr_perm = $perm_tkt_hash[perm_tkt]
  redirect "gnuidentity://?redirect_uri=http%3A%2F%2Ftestservice.gnu%3A4567%2Fclaims_gathering_cb%3Fpermission_ticket%3D#{perm_tkt}\
&client_id=#{$ego}&issue_type=ticket\
&requested_verified_attrs=#{curr_perm['req_ver_attr_http']}&nonce=1234"
end

def verify_claims(perm_tkt)
  curr_perm = $perm_tkt_hash[perm_tkt]
  curr_perm['claims_gathered'].each do |issuer_attr,claim|

    issuer = issuer_attr.split('.')[0]
    attrib = issuer_attr.split('.')[1]
    credential = "#{claim['issuer']}.#{claim['attribute']} -> #{claim['subject']} | #{claim['signature']} | #{claim['expiration']}"
    verify_cmd = "gnunet-credential --verify --issuer=#{$ego} --attribute=#{curr_perm["req_ver_attr"][issuer_attr]} --subject=#{claim['subject']} --credential=\"#{credential}\""
    response = `timeout 10 #{verify_cmd}`

    if response == ""
      claim['verified'] = false
    elsif response[-12..-1] == "Successful.\n"
      claim['verified'] = true
    end
  end
end

def issue_verified_attribute(issuer_attr,scope,curr_perm,count)
    issuer = issuer_attr.split('.')[0]
    attrib = issuer_attr.split('.')[1]
    requested_verified_attr = "#{attrib}_#{scope}_#{count}"
    curr_perm["req_ver_attr"][issuer_attr] = requested_verified_attr
    curr_perm["req_ver_attr_http"] += "#{requested_verified_attr},"
    response = `gnunet-namestore -p -z master-zone -a -n #{requested_verified_attr} -t ATTR -V "#{issuer} #{attrib}" -e 1h`
end

def resolve_policies(perm_tkt)
  policy_set_satisfied = true
  curr_perm = $perm_tkt_hash[perm_tkt]
  curr_perm['scopes_hash'].each do |scope_name,scope_value|
    if policy_set_satisfied == false
      break
    end
    scope_value['policy_sets'].each do |policy| 
      policy_satisfied = true
      policy.each do |issuer_attrib|
        issuer,attrib = issuer_attrib.split('.')
        if curr_perm['claims_gathered'][issuer_attrib] == nil || curr_perm['claims_gathered'][issuer_attrib]['verified'] == false
          policy_satisfied = false
          break
        end
      end
      if policy_satisfied == true
        policy_set_satisfied = true
        break
      else
        policy_set_satisfied = false
      end
    end
  end
  return policy_set_satisfied
end

def json(content)
    MultiJson.dump(content, pretty: true)
end

def decode_json(content)
    MultiJson.load(content, symbolize_keys: true)
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

def exchange_code_for_issuer(id_ticket, expected_nonce)
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
  p payload
  return payload
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
    if (!token.nil?)
      phone = token["phone"]
      exp = token["exp"] / 1000000
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
  p session
  if (!identity.nil?)
    token = $knownIdentities[identity]
    p token
  
    if (!token.nil?)
      redirect "/"
    end
  end

  if (!id_ticket.nil?)
    identity = exchange_code_for_issuer(id_ticket, $nonces[session["id"]])
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
        aat = SecureRandom.uuid
        authorization_code = SecureRandom.hex
        $aat[authorization_code] = [aat,client_id]
        valid_aat << aat
        redirect redirect_uri+"?code="+authorization_code
      end
    end
  redirect "/login"
end

post '/token' do
  if env['HTTP_AUTHORIZATION'] 
    auth_header = Base64.decode64(env['HTTP_AUTHORIZATION'].split(' ', 2).last || '').split(/:/, 2)
  else
    halt 401
  end

  client_id = auth_header[0]  
  client_secret = auth_header[1]
  authorization_code = params['code']
  
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
    
    perm_tkt = SecureRandom.uuid
    $perm_tkt_hash[perm_tkt] = {}
    $perm_tkt_hash[perm_tkt]['resource_owner_pkey'] = rsrc_id.split('.')[0]
    $perm_tkt_hash[perm_tkt]['resource_set_id'] = rsrc_id.split('.')[1]
    $perm_tkt_hash[perm_tkt]['scopes'] = scopes

    #get policies for scopes
    get_policies(perm_tkt)      
    status 201
    content_type :json 
    {:ticket => perm_tkt}.to_json
    
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
    perm_tkt = @request_payload["ticket"]

    #Check if ticket exists 
    if $perm_tkt_hash[perm_tkt]
      curr_perm = $perm_tkt_hash[perm_tkt]
      rsrc_id = perm_tkt['resource_set_id']
      scopes = perm_tkt['scopes']
    else
      status 400
      content_type :json 
      {:error => "expired_ticket"}.to_json
      halt 400, json({error: "expired_ticket"})
    end
    perm = curr_perm['permission_granted']
    if perm.nil? || perm == false
      status 403
      content_type :json
      halt 403, json({error: "need_info",
       error_details: {
           requesting_party_claims: {
               redirect_user: true,
               ticket: perm_tkt
             }
             }})
        
    end
    #Issue an RPT connecting resource & scope to RPT via permission ticket
    rpt = SecureRandom.hex
    curr_perm['rpt'] = rpt
    $rpt_scope[rpt] = perm_tkt
    status 200
    content_type :json 
    {:rpt => rpt}.to_json
  else
    halt 401
  end
end

#RPT claims gathering endpoint
get '/rpt_claims' do 
  claims_redirect_uri = params[:claims_redirect_uri]
  valid = validate_bearer_token(env,valid_aat)
  if valid
    perm_tkt = params[:ticket]
    #Check if ticket exists 
    if $perm_tkt_hash[perm_tkt]
      curr_perm = $perm_tkt_hash[perm_tkt]
      rsrc_id = curr_perm['resource_set_id']
      scopes = curr_perm['scopes']
    else
      status 400
      content_type :json 
      {:error => "expired_ticket"}.to_json
    end
    session["user"]
    gather_claims_request(perm_tkt)

  else
    halt 401
  end
end

#Claims gathering callback - once claims are gathered they are pushed here
get '/claims_gathering_cb' do
  token = params[:id_token]
  id_ticket = params[:ticket]
  perm_tkt = params[:permission_ticket]

  if (!id_ticket.nil?)
    curr_perm = $perm_tkt_hash[perm_tkt]
    jwt_token = exchange_code_for_token(id_ticket, 1234) #Change nonce here

    curr_perm["req_ver_attr"].each do |issuer_attr, req_attr|  
      credential_hash = jwt_token[req_attr]
      if credential_hash.nil?
        next
      end 
      curr_perm["claims_gathered"][issuer_attr]['issuer'] = credential_hash["issuer"]
      curr_perm["claims_gathered"][issuer_attr]['subject'] = credential_hash["subject"]
      curr_perm["claims_gathered"][issuer_attr]['attribute'] = credential_hash["attribute"]
      curr_perm["claims_gathered"][issuer_attr]['expiration'] = credential_hash["expiration"]
      curr_perm["claims_gathered"][issuer_attr]['signature'] = credential_hash["signature"]
    end
    verify_claims(perm_tkt)
    success = resolve_policies(perm_tkt)
    if success 
      curr_perm['permission_granted'] = true
      redirect curr_perm['claims_redirect_uri'] + "?authorization_state=claims_submitted"

    else
      curr_perm['permission_granted'] = false
      redirect curr_perm['claims_redirect_uri'] + "?authorization_state=not_authorized"
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
    rpt = @request_payload["token"]
    check_nil(rpt,"No RPT given")
    permission_ticket = $rpt_scope[rpt]
    check_nil(permission_ticket, "No permission associated with RPT")
    check_nil($perm_tkt_hash[permission_ticket], "Permission expired")
    curr_perm = $perm_tkt_hash[permission_ticket]
    resource_id = curr_perm["resource_set_id"]
    scopes = curr_perm["scopes"]
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