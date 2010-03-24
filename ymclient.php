<?php
	require_once realpath(dirname(__FILE__)) . "/OAuth.php";
	
	define('JSON11_ENDPOINT_URL', 'http://mail.yahooapis.com/ws/mail/v1.1/jsonrpc');
	define('OAUTH2_ENDPOINT_URL', 'https://api.login.yahoo.com/oauth/v2');
	
	class YMClient {
		
		function __construct($oaConsumerKey, $oaConsumerSecret) {			
			$this->oaConsumerKey = $oaConsumerKey;
			$this->oaConsumerSecret = $oaConsumerSecret;
			$this->signature = new OAuthSignatureMethod_HMAC_SHA1();
		}
		
		function __call($method, $arguments) {
			$this->oaRefreshedToken = null;
			
			list ($params, $tok) = $arguments;
			
			if(!$tok) {
				throw new YMClientException("Missing oauth access token", 0, null);
			}
			
			$request = new stdclass();
			$request->method = $method;
			$request->params = $params;
			
			// Create a loop around the cascade request in case 
			// the access token needs to be refreshed. 
			for($attemptNo = 0; $attemptNo < 2; $attemptNo++) {
				$ch = curl_init(JSON11_ENDPOINT_URL);
				curl_setopt($ch, CURLOPT_POST, 1);
				curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($request));
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				curl_setopt($ch, CURLOPT_HTTPHEADER, array(
					'Content-Type: application/json', 
					'Accept: application/json',
					$this->__build_oauth_header($tok)
				));
				$rawresponse = curl_exec($ch);
				$responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
				$responseContentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);			
				curl_close($ch);
				
				if($responseContentType === "application/json") {
					if($rawresponse == "") {
						throw new YMClientException("Empty response", 0, "The Ymail webservice returned an empty response");
					}
					
					$response = json_decode($rawresponse);
					
					// Cascade returned an "unauthorized" response. Try to refresh the access token
					if($responseCode == 401) {
						
						// The token expired, attempt to refresh it
						if(isset($response->error->description) && preg_match("/token_expired/", $response->error->description)) {
							$tok = $this->__oauth_refresh_access_token($tok);
							$this->oaRefreshedToken = $tok;
						}
						
						// Some other error occured. Forward along info about it.
						else {
							throw new YMClientException("Ymail request failed", $responseCode, $response);
						}
					}
					
					else {
						return $response->result;
					}
				}
			
				else {
					// Cascade returned a malformed response. Forward along info about it.
					throw new YMClientException("Ymail request failed", $responseCode, "Bad response from Ymail: HTTP $responseCode, Content-Type: $responseContentType");
				}
			}
		}
		
		function oauth_get_access_token($tok) {
			$oaReqParams = array(
				'oauth_nonce' => OAuthRequest::generate_nonce(),
				'oauth_timestamp' => OAuthRequest::generate_timestamp(),
				'oauth_consumer_key' => $this->oaConsumerKey,
				'oauth_version' => '1.0',
				'oauth_signature_method' => 'PLAINTEXT', //'HMAC-SHA1' //FIXME: Even needed??
				'oauth_token' => $tok['oauth_token']
			);
			
			// If the passed token has a verifier add it to the OAuth parameters. This
			// only happens when requesting a new access token (instead of doing a refresh 
			// on an existing access token which don't have verifiers)
			if(isset($tok['oauth_verifier'])) {
				$oaReqParams['oauth_verifier'] = $tok['oauth_verifier'];
			}
			
			// If the passed token has a session handle add it to the OAuth parameters. 
			// This happens when we are refreshing an access token. 
			if(isset($tok['oauth_session_handle'])) {
				$oaReqParams['oauth_session_handle'] = $tok['oauth_session_handle'];
			}
			
			// Do the request
			$request = new OAuthRequest('GET', (OAUTH2_ENDPOINT_URL . "/get_token"), $oaReqParams);
			$url = $request->to_url() . '&oauth_signature=' . $this->oaConsumerSecret . '%26' . $tok['oauth_token_secret'];
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($ch, CURLOPT_URL, $url);
			$resp = curl_exec($ch);
			curl_close($ch);
			parse_str($resp, $newtok);
									
			if(!$newtok['oauth_token'] || !$newtok['oauth_token_secret']) {				
				throw new YMClientException("Access token request failed", 0, $resp);	
			}
			
			return $newtok;
		}
		
		function oauth_get_request_token($callbackURL) {
			$request = new OAuthRequest('GET', (OAUTH2_ENDPOINT_URL . "/get_request_token"), array(
				'oauth_nonce' => OAuthRequest::generate_nonce(),
				'oauth_timestamp' => OAuthRequest::generate_timestamp(),
				'oauth_version' => '1.0',
				'oauth_signature_method' => 'HMAC-SHA1',
				'oauth_consumer_key' => $this->oaConsumerKey,
				'oauth_callback' => $callbackURL));
			
			$url = $request->to_url() . "&oauth_signature=" . $this->signature->build_signature($request, new OAuthConsumer('', $this->oaConsumerSecret), NULL);
			
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($ch, CURLOPT_URL, $url);
			$resp = curl_exec($ch);
			curl_close($ch);
			parse_str($resp, $tok);
			if(!$tok['oauth_token'] || !$tok['oauth_token_secret']) {				
				throw new YMClientException("Request token request failed", 0, $resp);	
			}
			
			return array($tok, (OAUTH2_ENDPOINT_URL . "/request_auth?oauth_token=" . $tok['oauth_token']));
		}
		
		function oauth_get_refreshed_token() {
			if($this->oaRefreshedToken) {
				return $this->oaRefreshedToken;
			}
		}
		
		public static function oauth_token_from_query_string($s) {
			parse_str($s, $tokens);
			return $tokens;
		}
		
		public static function oauth_token_to_query_string($tok) {
			$a = array();
			foreach($tok as $k => $v) {
				array_push($a, ("$k=" . OAuthUtil::urlencodeRFC3986($v)));
			}
			
			return implode("&", $a);
		}
		
		private function __oauth_refresh_access_token($tok) {
			if(!isset($tok['oauth_session_handle'])) {
				throw new YMClientException("Failed to refresh access token without a session handle.", 0, null);
			}
			
			return $this->oauth_get_access_token($tok);
		}
		
		private function __build_oauth_header($tok) {
			$request = new OAuthRequest('POST', JSON11_ENDPOINT_URL, array(
				'oauth_nonce' => OAuthRequest::generate_nonce(),
				'oauth_timestamp' => OAuthRequest::generate_timestamp(),
				'oauth_version' => '1.0',
				'oauth_signature_method' => 'HMAC-SHA1',
				'oauth_consumer_key' => $this->oaConsumerKey,
				'oauth_token' => $tok['oauth_token']
			));
			
			$request->sign_request($this->signature, new OAuthConsumer('', $this->oaConsumerSecret), new OAuthToken('', $tok['oauth_token_secret']));
			return $request->to_header();
		}
	}
	
	class YMClientException extends Exception {
		private $errorCode;
		private $detail;

		public function __construct($message, $code, $detail) {
			parent::__construct($message);
			$this->errorCode = $code;
			$this->detail = $detail;
		}

		public function getErrorCode() {
			return $this->errorCode;
		}

		public function getDetail() {
			return $this->detail;
		}
	}
?>