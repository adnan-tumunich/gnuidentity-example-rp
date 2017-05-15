require 'sinatra'
require 'sinatra/cookies'
require 'json'
require 'base64'
require 'date'
require 'net/http'
require 'securerandom'

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
$aat = {}
$knownClients = {'random_client_id' => 'lksajr327048olkxjf075342jldsau0958lkjds'}



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

