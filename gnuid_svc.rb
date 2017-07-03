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



#TODO: Delete after testing
#Sample JWT for testing
jwt_token_dummy = 
{
  "iss": "07TAXQQ3VW71F33JA8ZEZ37EW3KZ94PYNJNCNS9X720KRCWMSCSG",
  "aud": "YFJMNXKCQX99KECSE5MNQ3P1PTJMGBRNSBDCPFXZA3MM0HKNHNFG",
  "sub": "07TAXQQ3VW71F33JA8ZEZ37EW3KZ94PYNJNCNS9X720KRCWMSCSG",
  "nbf": 1496134978288178,
  "iat": 1496134978288178,
  "exp": 1496136778288178,
  "nonce": "1234",
  "user": {
    "issuer": "KNKSSJW5X9ERZ9AJ88D202WPFEGCZFJ2X8E5R90C8DNXDQXPQ8YG",
    "subject": "07TAXQQ3VW71F33JA8ZEZ37EW3KZ94PYNJNCNS9X720KRCWMSCSG",
    "signature": "AyoKojAYKLMJNF1VldHY5g0zikT9g1J7B6Iq8m/e7p8JF9PpB3hB0B5sqc/UGOHgQxGTCxAQyK/EF4PREYbpww===",
    "attribute": "student",
    "expiration": 1495885180692747
  }
}



$perm_tkt_hash = {"7d282e1b-28b3-4ecf-979f-2969078daf57" => {
   "resource_owner_pkey" => "ropkey",
   "resource_set_id" => "1234",
   "scopes" => ["read", "write"],
   "claims_redirect_uri" => "http://192.168.33.10",
   "claims_array" => ["RWPKFRY7AKDBXJB8YWRJ0N1R3FB69VP3MFC28QZ0601VNCSRJMT0.member", "RWPKFRY7AKDBXJB8YWRJ0N1R3FB69VP3MFC28QZ0601VNCSRJMT0.student"],
   "req_ver_attr" => ["hello", "student"],

   
    "scopes_hash" => {
      "read" => {
          "policy_name" => "182423_read",
          "policy_sets" => [["Issuer1.attr1", "Issuer2.attr2" ], ["Issuer3.attr3"]]
                    
      },
       "write" => {
          "policy_name" => "182423_write",
          "policy_sets" => [["Issuer5.attr5"]]
                    
      }
   }    
  }
} 

=begin
permission_ticket hash

Resource set id in request: resource_owner_pkey.resource_set_id

perm_tkt_hash = {"7d282e1b-28b3-4ecf-979f-2969078daf57" => {
   resource_owner_pkey: 
   resource_set_id: 
   scopes => [],
   claims_redirect_uri => " ",
   claims_array => ["Issuer.attribute", "Issuer2.attr2", "Issuer3.attr3"]
   req_ver_attr => ["attr_by_self", "attr2_by_self",...]
   req_ver_attr_http => "attr_by_self&"
   "claims_array" => ["Issuer1.attr1", "Issuer2.attr2", "Issuer3.attr3"],
   "permission_granted" => false
   claims_gathered => {
       "Issuer.attribute" => { 
                                  issuer:
                                  attribute: 
                                  gathered_claims:
                                  verified: 
                                  }
       "Issuer2.attributre2" => {
                                  issuer: Issuer2
                                  attribute: attribute2
                                  signature:
                                  expiration: 
                                  verified: true/false
                                  }
   }
    scopes_hash => {
      "read" => {
          policy_name => "182423_read"
          "policy_sets" => [["Issuer.attribute", "Issuer2.attribute2" ], ["Issuer3.attribute3"]] 
          // Each sub-array is a complete permission set. So if one sub-array is satisfied then permission can be granted
         
           
      }
   }    
} 
  
=end



#Self EGO - for GNS
# Currently this doesn't work - only works for master zone 
#ego = '87DYZCD8DV2ENR8RC2S425FZPB93CV56XHG4DAQVVZ93RCWES6M0'
#ego_name = 'example-rp'
$ego = 'YFJMNXKCQX99KECSE5MNQ3P1PTJMGBRNSBDCPFXZA3MM0HKNHNFG'
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
  curr_perm["req_ver_attr"] = []
  curr_perm["req_ver_attr_http"] = "" 
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

        curr_perm['claims_gathered'][iss_attr] = {}
      end
    end
  end
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
  curr_perm["claims_gathered"] = {}
  curr_perm['claims_gathered'].each do |claim|
    credential = "#{claim['issuer']}.#{claim['attribute']} -> #{claim['subject']} | #{claim['signature']} | #{claim['expiration']}"
    verify_cmd = "gnunet-credential --verify --issuer=#{ego} --attribute=#{requested_verified_attr} --subject=#{jwt_token_credential[:subject]} --credential=\"#{credential}\""
    response = `timeout 10 #{verify_cmd}`

    if response == ""
      claim['verified'] = false
    elsif response[-12..-1] == "Successful.\n"
      claim['verified'] = true
    end
  end

  def issue_verified_attribute(issuer_attr,scope,count)
      issuer = issuer_attr.split('.')[0]
      attrib = issuer_attr.split('.')[1]
      requested_verified_attr = "#{attrib}_#{scope}_#{count}"


      curr_perm["req_ver_attr"].push(requested_verified_attr)
      curr_perm["req_ver_attr_http"] += "#{requested_verified_attrib},"
      curr_perm["req_ver_attr_http"][-1] = ''
      response = `gnunet-namestore -p -z master-zone -a -n #{requested_verified_attr} -t ATTR -V "#{issuer} #{attrib}" -e 1h`
  end






  #sample code. needs to be changed
  curr_perm["claims_gathered"] = {}
  curr_perm["claims_gathered"] = {}

curr_perm["claims_gathered"] = {}
  curr_perm["claims_gathered"]["attr2"] = {
     'issuer' => "Issuer2",
      'attribute' => "attr2", 
      'gathered_claims' => {"attr2" => {"issuer" => "FLJKJLAFJL", "attribute" => "attr2", "subject": "LAKSDJFLOWEUR"}},
      'verified' => true
  }
  curr_perm["claims_gathered"]["attr5"] = {
     'issuer' => "Issuer5",
      'attribute' => "attr5", 
      'gathered_claims' => {"attr5" => {"issuer" => "FLJKJLAFJL", "attribute" => "atttr5", "subject": "LAKSDJFLOWEUR"}},
      'verified' => true
  }

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




# policy_hash -> {name: '123_read', value: ['XW0HP8SEQZ4SQGEH3PSHBB9E0TKDCQC6DNCX9QAYS0K5XXHBJJ20.student']}
#permission_value -> [resource_id, [scopes]]
def resolve_policy(permission_ticket)

  policy = get_policy(resource_set_id,scopes)
  check_empty(policy,"Invalid scopes")
  resource_id,action = policy["name"].split('_')
  policy_hash = {}
  policy["value"].each do |condition|
    issuer = condition.split('.')[0]
    policy_hash[issuer] = condition.split('.')[1]
  end
  return policy_hash
end




def issue_attrs

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





get '/test_cmd' do

  #r = `gnunet-gns -u 18687878_read.MFVZ0430P5CRHSYY8K23X45J06YYTXSJFG7PCTR608WZMJMBVBWG.zkey -t POLICY --raw`
  #x = r.split("\n")
  #puts x
  #get_policies("7d282e1b-28b3-4ecf-979f-2969078daf57")
  #gather_claims_request("7d282e1b-28b3-4ecf-979f-2969078daf57")
  verify_claims("7d282e1b-28b3-4ecf-979f-2969078daf57")
  perm = resolve_policies("7d282e1b-28b3-4ecf-979f-2969078daf57")
  puts "Permission granted: #{perm}"
  "hello"
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

    
    perm_tkt = SecureRandom.uuid
    $perm_tkt_hash[perm_tkt] = {}
    $perm_tkt_hash[perm_tkt]['resource_owner_pkey'] = rsrc_id.split('.')[0]
    $perm_tkt_hash[perm_tkt]['resource_set_id'] = rsrc_id.split('.')[1]
    $perm_tkt_hash[perm_tkt]['scopes'] = scopes

    #get policies for scopes
    get_policies(perm_tkt)      

    puts $perm_tkt_hash.inspect
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
               ticket: perm_tkt
             }
             }})
        
    end

    #Issue an RPT connecting resource & scope to RPT via permission ticket
    rpt = SecureRandom.hex
    curr_perm['rpt'] = rpt
    rpt_scope[rpt] = perm_tkt

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
  claims_redirect_uri = params[:claims_redirect_uri]
  valid = validate_bearer_token(env,valid_aat)
  #if valid
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

    puts "rpt claims"

    gather_claims_request(perm_tkt)


    #TODO nonce should be a random integer 

  #else
 #   halt 401
 # end
end


#Claims gathering callback - once claims are gathered they are pushed here
get '/claims_gathering_cb' do
  token = params[:id_token]
  id_ticket = params[:ticket]
  perm_tkt = params[:permission_ticket]

  puts "here1"
  puts "id ticket #{id_ticket} \n"
  puts "perm #{perm_tkt}"
 
  if (!id_ticket.nil?)
    curr_perm = $perm_tkt_hash[perm_tkt]
    puts "here"
    jwt_token = exchange_code_for_token(id_ticket, 1234) #Change nonce here
    puts "JWT token"
    p jwt_token
    puts claims_redirect_uris.inspect
    puts perm_tkt.inspect
    puts jwt_token.class
    gathered_claims[perm_tkt] = jwt_token
    verify_claims(perm_tkt)
    success = resolve_policies(perm_tkt)
    if success 
      curr_perm['permission_granted'] = true
      redirect curr_perm['claims_redirect_uri'] + "?authorization_state=claims_submitted"

    else
      gathered_claims[permission_ticket] = nil
      curr_perm['permission_granted'] = false
      redirect claims_redirect_uris[permission_ticket] + "?authorization_state=not_authorized"
      
    end

  end


end




get '/claims_gathering_cb_dummy' do
  

  jwt_token = jwt_token_dummy 
  requested_verified_attr = "user"
  #subject = "07TAXQQ3VW71F33JA8ZEZ37EW3KZ94PYNJNCNS9X720KRCWMSCSG" #Adnan
  #issuer = "YFJMNXKCQX99KECSE5MNQ3P1PTJMGBRNSBDCPFXZA3MM0HKNHNFG" #master-zone
  #Q?: Is the subject iss from JWT or subject from credential in JWT? 
  
  puts "JWT token"
  p jwt_token

  permission_ticket = "7d282e1b-28b3-4ecf-979f-2969078daf57"

  puts claims_redirect_uris.inspect
  puts permission_ticket.inspect
  puts jwt_token.class
  gathered_claims[permission_ticket] = jwt_token
  
  #verify policy here
  requested_verified_attr = "user"
  jwt_token_credential = jwt_token[requested_verified_attr.to_sym]

  puts jwt_token_credential

  credential = "#{jwt_token_credential[:issuer]}.#{jwt_token_credential[:attribute]} -> #{jwt_token_credential[:subject]} | #{jwt_token_credential[:signature]} | #{jwt_token_credential[:expiration]}"
  puts credential


  verify_command = "gnunet-credential --verify --issuer=#{ego} --attribute=#{requested_verified_attr} --subject=#{jwt_token_credential[:subject]} --credential=\"#{credential}\""
  puts verify_command


  #TODO: timeout 10 - increase to 30
  response = `timeout 10 #{verify_command}`

  if response == ""
    success = false
  elsif response[-12..-1] == "Successful.\n"
    success = true
  end
  

  if success 
    redirect claims_redirect_uris[permission_ticket] + "?authorization_state=claims_submitted"
  else
    gathered_claims[permission_ticket] = nil
    redirect claims_redirect_uris[permission_ticket] + "?authorization_state=not_authorized"
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