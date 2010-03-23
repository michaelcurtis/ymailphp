<?php
/**
 * The MIT License
 * 
 * Copyright (c) 2008 OAuth.net
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * 
 */

	require_once realpath(dirname(__FILE__)) . "/OAuth.php";
	
	define('JSON11_ENDPOINT_URL', 'http://mail.yahooapis.com/ws/mail/v1.1/jsonrpc');
	define('OAUTH2_ENDPOINT_URL', 'https://api.login.yahoo.com/oauth/v2');
	define('REQUEST_TOKEN_COOKIE_NAME', 'rt');
	define('ACCESS_TOKEN_COOKIE_NAME', 'at');
	
	class YMClient {
		
		function __construct($oaConsumerKey, $oaConsumerSecret, $callbackURL) {			
			$this->oaConsumerKey = $oaConsumerKey;
			$this->oaConsumerSecret = $oaConsumerSecret;
			$this->callbackURL = $callbackURL;
			$this->signature = new OAuthSignatureMethod_HMAC_SHA1();
		}
		
		function __call($method, $arguments) {
			$request = new stdclass();
			$request->method = $method;
			$request->params = $arguments;
			
			// Create a loop around the cascade request in case 
			// the access token needs to be refreshed. 
			for($attemptNo = 0; $attemptNo < 2; $attemptNo++) {	
				
				$tok = $this->__oauth_get_token();
				
				// Use the access token to create an oauth header
				$oaRequestHeader = $this->__get_oauth_header($tok);
				
				// Make the cascade request
				$ch = curl_init(JSON11_ENDPOINT_URL);
				curl_setopt($ch, CURLOPT_POST, 1);
				curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($request));
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', $oaRequestHeader));
				$rawresponse = curl_exec($ch);
				$responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
				$responseContentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);			
				curl_close($ch);
				
				if($responseContentType === "application/json") {
					if($rawresponse == "") {
						// An empty response was returned. :(
						throw new YMClientException("Empty response", 0, "The Ymail webservice returned an empty response");
					}
								
					if(property_exists($response, "error") && !is_null($response->error)) {
						// Cascade returned an error. 
						if($response->error == "Client.ExpiredCredentials") {							
							$this->_oauth_refresh_access_token($tok);
						}
					
						else {
							// It was an error that we don't know how to handle, pass it along. 
							throw new YMClientException($response->error->message, $response->error->code, $response->error->detail);
						}
					}
					
					else {
						// Return the response.
						$response = json_decode($rawresponse);
						return $response->result;
					}
				}
			
				else {
					// Some kind of invalid response was returned from the webservice (like
					// HTML). There is a bug in the ymail webservice that causes it to throw
					// a 999 error when OAuth access tokens expire. Typically 999 means that 
					// the client has crossed rate limits. 
					
					//FIXME: remove this when ymail fixes the above referenced bug
					if($responseCode == 999) {						
						// Refresh the access token and try again
						$this->_oauth_refresh_access_token($tok);
					}
					
					// Huge hack! Ymail API is returning an XML error when the access token 
					// expires even though the request was for JSON. 
					//FIXME: remove this when Cascade fixes their shit. 
					else if(preg_match("/token_expired/", $rawresponse)) {
						// The OAuth credentials expired, refresh them.
						$this->_oauth_refresh_access_token($tok);
					}
					
					else {
						throw new YMClientException("Cascade request failed", $responseCode, "Bad response from Cascade: HTTP $responseCode, Content-Type: $responseContentType");
					}
				}
			}
		}
		
		private function __oauth_get_token() {
			// We already have an access token stashed in a cookie. 
			if($_COOKIE[ACCESS_TOKEN_COOKIE_NAME]) {
				parse_str($_COOKIE[ACCESS_TOKEN_COOKIE_NAME], $tokens);
				return $tokens;
			}
			
			// We have already acquired a request token and are now handling 
			// a redirect back to the app. We can use the query params passed
			// to us to mint a new access token. 
			else if($_COOKIE[REQUEST_TOKEN_COOKIE_NAME] && $_REQUEST['oauth_verifier'] && $_REQUEST['oauth_token']) {
				$tok = $this->__oauth_token_from_query_string($_COOKIE[REQUEST_TOKEN_COOKIE_NAME]);
				
				// Make sure the token from the callback matches the cookie
				if($tok['oauth_token'] != $_REQUEST['oauth_token']) {
					throw new YMClientException("Cookie and URL disagree about request token value", 0);
				}
				
				$tok['oauth_verifier'] = $_REQUEST['oauth_verifier'];
													
				return $this->__oauth_get_access_token($tok);
			}
			
			// We have not acquired a request token yet (the user has not)
			// granted our application access to their data yet. 
			else {
				$this->__oauth_get_request_token();
			}
		}
		
		private function __oauth_get_access_token($rtok) {
			$oaReqParams = array(
				'oauth_nonce' => OAuthRequest::generate_nonce(),
				'oauth_timestamp' => OAuthRequest::generate_timestamp(),
				'oauth_consumer_key' => $this->oaConsumerKey,
				'oauth_version' => '1.0',
				'oauth_signature_method' => 'PLAINTEXT', //'HMAC-SHA1' //FIXME: Even needed??
				'oauth_token' => $rtok['oauth_token']
			);
			
			// If the passed token has a verifier add it to the OAuth parameters. This
			// only happens when requesting a new access token (instead of doing a refresh 
			// on an existing access token which don't have verifiers)
			if(isset($rtok['oauth_verifier'])) {
				$oaReqParams['oauth_verifier'] = $rtok['oauth_verifier'];
			}
			
			// If the passed token has a session handle add it to the OAuth parameters. 
			// This happens when we are refreshing an access token. 
			if(isset($rtok['oauth_session_handle'])) {
				$oaReqParams['oauth_session_handle'] = $rtok['oauth_session_handle'];
			}
			
			// Do the request
			$request = new OAuthRequest('GET', (OAUTH2_ENDPOINT_URL . "/get_token"), $oaReqParams);
			$url = $request->to_url() . '&oauth_signature=' . $this->oaConsumerSecret . '%26' . $rtok['oauth_token_secret'];
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($ch, CURLOPT_URL, $url);
			$resp = curl_exec($ch);
			curl_close($ch);
			parse_str($resp, $tok);
									
			if(!$tok['oauth_token'] || !$tok['oauth_token_secret']) {				
				throw new YMClientException($resp, 0);	
			}
			
			// Expire our request token cookie. Don't need it anymore. 
			setcookie(REQUEST_TOKEN_COOKIE_NAME, "", time()-3600);
						
			// Persist the new access token in a cookie and return it.
			setcookie(ACCESS_TOKEN_COOKIE_NAME, $this->__oauth_token_to_query_string($tok));			
			return $tok;
		}
		
		private function __oauth_get_request_token() {
			$request = new OAuthRequest('GET', (OAUTH2_ENDPOINT_URL . "/get_request_token"), array(
				'oauth_nonce' => OAuthRequest::generate_nonce(),
				'oauth_timestamp' => OAuthRequest::generate_timestamp(),
				'oauth_version' => '1.0',
				'oauth_signature_method' => 'HMAC-SHA1',
				'oauth_consumer_key' => $this->oaConsumerKey,
				'oauth_callback' => $this->callbackURL));
			
			$url = $request->to_url() . "&oauth_signature=" . $this->signature->build_signature($request, new OAuthConsumer('', $this->oaConsumerSecret), NULL);
			
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($ch, CURLOPT_URL, $url);
			$resp = curl_exec($ch);
			curl_close($ch);
			parse_str($resp, $tokens);
			if(!$tokens['oauth_token'] || !$tokens['oauth_token_secret']) {				
				throw new YMClientException($resp, 0);	
			}
			
			$tok = new OAuthToken($tokens['oauth_token'], $tokens['oauth_token_secret']);
						
			// Set a cookie with the request token/secret then redirect...
			setcookie(REQUEST_TOKEN_COOKIE_NAME, $tok->to_string());
			$loginURL = OAUTH2_ENDPOINT_URL . "/request_auth?oauth_token=" . $tokens['oauth_token'];
			header("Location: $loginURL");
		}
		
		private function _oauth_refresh_access_token($tok) {			
			if(!isset($tok['oauth_session_handle'])) {
				throw new YMClientException("Cannot refresh access token without a session handle.", 0);
			}
						
			return $this->__oauth_get_access_token($tok);
		}
		
		private function __oauth_token_from_query_string($s) {
			parse_str($s, $tokens);
			return $tokens;
		}
		
		private function __oauth_token_to_query_string($tok) {
			$a = array();
			foreach($tok as $k => $v) {
				array_push($a, ("$k=" . OAuthUtil::urlencodeRFC3986($v)));
			}
			
			return implode("&", $a);
		}
		
		private function __get_oauth_header($tok) {
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