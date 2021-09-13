// Logging with the script name is super helpful!
function logger() {
  print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

var HttpSender    = Java.type('org.parosproxy.paros.network.HttpSender');
var ScriptVars    = Java.type('org.zaproxy.zap.extension.script.ScriptVars');
var HtmlParameter = Java.type('org.parosproxy.paros.network.HtmlParameter')
var COOKIE_TYPE   = org.parosproxy.paros.network.HtmlParameter.Type.cookie;
var ForcedUser    = org.parosproxy.paros.control.Control.getSingleton()
                        .getExtensionLoader().getExtension(
                            org.zaproxy.zap.extension.forceduser.ExtensionForcedUser.class
                        );

function sendingRequest(msg, initiator, helper) {
  
  if (initiator === HttpSender.AUTHENTICATION_INITIATOR) {
     logger("Sending authentication Request")
     logger(ScriptVars.getScriptVars("jwtScript.js"))
     var customHeaders = ScriptVars.getScriptVars("jwtScript.js")
     for (var key in customHeaders) {
        msg.getRequestHeader().setHeader(key, customHeaders[key])
     }
  

     return msg;
  }

  logger('Is forced user: '+ ForcedUser.isForcedUserModeEnabled())
  if (!ForcedUser.isForcedUserModeEnabled()) {return;}
  
  var token = ScriptVars.getGlobalVar("header_token")
  if (!token) {
     logger('Undefined token value')
     return;
  }
  
  logger('Url: ' + msg.getRequestHeader().getURI().toString())
  logger("Adding authorization header token" + (' ' + token).slice(0, 20))
  var headers = msg.getRequestHeader();
  msg.getRequestHeader().setHeader('Authorization', token);
  return msg;
}

function responseReceived(msg, initiator, helper) {
  var resbody     = msg.getResponseBody().toString()
  var resheaders  = msg.getResponseHeader()

  if (initiator != HttpSender.AUTHENTICATION_INITIATOR) {
     return;
  }

  var contextId = msg.getRequestingUser().getContextId()
  var user = ForcedUser.getForcedUser(contextId)

  logger('Trying to authenticate with user: '+ user.getName())
  if (!ForcedUser.isForcedUserModeEnabled()) {return;}

  logger("Handling auth response")
  logger("Server Response: "+resheaders.getStatusCode())
  if (resheaders.getStatusCode() > 299) {
   
    logger("Auth failed for user: " + user.getName())
    return;
  } 

  logger("Authentication request was successful")

  //Retrieve Authorization Token from header
  token = msg.getResponseHeader().getHeader("Authorization")
  
  logger("token:"+ token)
  logger("ResponseHeader: "+resheaders)
  logger("ResponseBody: "+resbody)

  // If auth request was not succesful move on
  if (token.length==0) {return;}
  
  // @todo abstract away to be configureable
  logger("Capturing token for Authorization\n" + token)
  ScriptVars.setGlobalVar("header_token", token)
}







