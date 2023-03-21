<?php

/*   Copyright 2023 Plancksoft

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.*/

	class Security {
		// This array serves as a malicious code signature datatable and requires frequent updating
		// to stay alert to the newest SQLi and XSS attacks.
		private static $MALICIOUS_INPUT = [ 
			"<script>", "</script>", "<", ">"
		];
		
		public static $PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----
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
wF6e/slHzV87Hz9AgL8vmEbtMixr854=
-----END PRIVATE KEY-----";
		
		public static $PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3XBEEG4ewo+1Ei+DZb1G
sdOL7o8qMDTqdtv5H41vwZ4mdIglbbnbz6RzYZ0wwrCZkvsTpCS5iLV0TImBsN0h
C8A9xFMKzkjrEe4jlfZBGQD2ugA9sDBZ77/dKl7z0G1Xu3qkk+8v+qVg5D93ktwz
2MS2XQNlUSKv4PlMzlrGY2Z6z+KvY+LQ8mAdD/51CioPr6P41q1Z0GA8S4kCwzLp
cy6DRY95/5/azEETq3lhGwEHi6Y2aMaVryD4MMOFmIooccJwa1AsYtqFg9lqJq1F
SgTYcCsTbVBQxs79wxmt9wkisSwbd1Lq/OcLKayb1HPh+Azrv8dWV9s0lPeS9Wnq
EJ9od+/9TgcZbrpsvNRMxjWRYMRHxsqv/vGj4BgWe4lZNNPTE+bm+VRhRFqHGaYb
SITXbPcideCbtfL2zJqZ95MxpL8LYvmK1je45/uGucs+b0MeRBwOTrxyd2/PHpRe
5bsAmR30zJtt93Zo8mdfBe+qeIlkWbfmX09Q0HDEdbWLSM1zuSBBR05Uo26TjCaD
suc5TKODwG+ydEKGzJWBdxf+pEE/4qg55aA9ibhgZB29PE3mMZTVQyb2gx7g84go
l6NF73cdjbq+2lWRuqP/yhD9sEHoO4j3qQNBrtAGlg14xCdToZrGerrQHbcL5bLv
RYBUu7grkLOVzw0E0r4YyUECAwEAAQ==
-----END PUBLIC KEY-----";
		
		public static function BlockInvalidTraffic($RequestData = "")
		{
			try
			{
				if ($RequestData !== "")
				{
					$IP = "";
					
					if(!empty($_SERVER['REMOTE_ADDR']))
					{
						$IP = $_SERVER['REMOTE_ADDR'];

						if (isset($IP) && $IP !== "")
						{
							if (isset($RequestData["Token"]))
							{
								if ($RequestData["Token"] !== "")
								{
									$UID = Token::Decode($RequestData["Token"])["user"]["uid"];
									
									if ($UID !== "")
									{
										$Client = new MongoDB\Client;
										$AuthBlockedCollection = $Client->ScholarFindr->AuthBlocked;
										
										$Options = ['sort' => ['timestamp' => -1], 'limit' => 100];
										$Filter = ['$or' => [
													['ip' => $IP], ['uid' => $UID]
										]];
										$BlockedMatches = $AuthBlockedCollection->find($Filter, $Options);
										
										if (isset($BlockedMatches) && $BlockedMatches !== null)
										{
											$FoundMatch = false;
											$MatchReason = "";
											$BlockDate = "";
											
											foreach($BlockedMatches as $BlockedMatch)
											{
												if ($BlockedMatch->ip === $IP)
												{
													$FoundMatch = true;
													$BlockDate = $BlockedMatch->entrydate;
													$MatchReason = $BlockedMatch->reason;
												} else {
													$FoundMatch = false;
												}
											}
											if ($FoundMatch)
											{
												$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => -2, "message" => Settings::$PrefixLog . "has refused the connection due to an IP block issued on your IP Address: " . $IP . " on " . $BlockDate . ". Reason: " . $MatchReason . "."], true)), $PUBLIC_RSA_KEY);
												$ResponseSignature = Security::SignMessage($EncryptedResponse);
												
												echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
												Logger::Log(Settings::$LogPrefix, "has refused the connection due to an IP block issued on your IP Address: " . $IP . " on " . $BlockDate . ". Reason: " . $MatchReason);
												die();
											}
										}
									} else {
										$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "An invalid request was supplied."], true)), $PUBLIC_RSA_KEY);
										$ResponseSignature = Security::SignMessage($EncryptedResponse);
										
										echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
										Logger::Log(Settings::$LogPrefix, "has refused the connection due to an invalid supplied request");
										die();
									}
								} else {
									$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "An empty API Token was supplied."], true)), $PUBLIC_RSA_KEY);
									$ResponseSignature = Security::SignMessage($EncryptedResponse);
									
									echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
									
									Logger::Log(Settings::$LogPrefix, "has refused the connection due to an empty supplied API Token");
									die();
								}
							}
						} else {
							$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$PrefixLog . "has refused the connection due to a failure in acquiring your IP Address."], true)), $PUBLIC_RSA_KEY);
							$ResponseSignature = Security::SignMessage($EncryptedResponse);
							
							echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
							
							Logger::Log(Settings::$LogPrefix, "has refused the connection due to a failure in acquiring your IP Address");
							die();
						}
					}
				} else {
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => -2, "message" => "No request was supplied to the NeatVibez firewall system."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					
					Logger::Log(Settings::$LogPrefix, "has refused the connection due to a missing supplied request");
					return false;
				}
			} catch (Exception $Exception)
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "An invalid request was supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				
				Logger::Log(Settings::$LogPrefix, "has refused the connection due to a missing supplied request");
				die();
			}
		}
		
		public static function BlockReason($RequestData = "", $Reason = "", $PUBLIC_RSA_KEY = "")
		{
			try
			{
				if ($RequestData !== "")
				{
					$Client = new MongoDB\Client;
					$AuthBlockedCollection = $Client->ScholarFindr->AuthBlocked;
					
					$UID = Token::Decode($RequestData["Token"])["user"]["uid"];
					$IP = "";

					if(!empty($_SERVER['REMOTE_ADDR']))
					{
						$IP = $_SERVER['REMOTE_ADDR'];
						if (isset($IP) && $IP !== "")
						{
							$AuthBlockEntry = $AuthBlockedCollection->InsertOne(["uid" => $UID, "ip" => $IP, "entrydate" => date("d/m/Y H:i:s"), "reason" => $Reason]);
							if ($AuthBlockEntry->getInsertedId() != "")
							{
								$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => -2, "message" => "The NeatVibez firewall system has detected input parameters with malicious intent and has therefore refused the connection. Your Account and IP Address were also added to the blocked list."], true)), $PUBLIC_RSA_KEY);
								$ResponseSignature = Security::SignMessage($EncryptedResponse);
								
								echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
								Logger::Log(Settings::$LogPrefix, "has refused the connection due to a detection of malicious input and was added to the DB log");
								die();
							} else {
								$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => -2, "message" => "The NeatVibez firewall system has detected input parameters with malicious intent and has therefore refused the connection without blocking the Account or IP Address."], true)), $PUBLIC_RSA_KEY);
								$ResponseSignature = Security::SignMessage($EncryptedResponse);
								
								echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
								Logger::Log(Settings::$LogPrefix, "has refused the connection due to a detection of malicious input, but was not added to the DB log due to a failure in accessing the AuthBlocked collection");
								die();
							}
						}
					}
				} else {
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => -2, "message" => "Blocking has failed as no request input was supplied to the NeatVibez firewall system."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					Logger::Log(Settings::$LogPrefix, "was unable to block the source of request as no request input was supplied to the NeatVibez firewall system");
					return false;
				}
			} catch (Exception $Exception)
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => -2, "message" => "Blocking has failed as no request input was supplied to the NeatVibez firewall system."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				Logger::Log(Settings::$LogPrefix, "was unable to block the source of request as no request input was supplied to the NeatVibez firewall system");
				return false;
			}
		}
		
		public static function Secure($RequestData = "", $PUBLIC_RSA_KEY = "")
		{
			try
			{
				if ($RequestData !== "")
				{
					$DetectionResults = Security::Scan($RequestData, $PUBLIC_RSA_KEY);
					
					if (gettype($DetectionResults) === "Array" || gettype($DetectionResults) === "array")
					{
						return $DetectionResults;
					}
					else {
						Security::BlockReason($RequestData, "User has supplied malicious code through their requests", $PUBLIC_RSA_KEY);
					}
				} else {
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => -2, "message" => "No request was supplied to the NeatVibez firewall system."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					Logger::Log(Settings::$LogPrefix, "has refused the connection due to a missing supplied request");
					return false;
				}
			} catch(Exception $Exception)
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "An invalid request was supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				Logger::Log(Settings::$LogPrefix, "has refused the connection due to an invalid supplied request");
				die();
			}
		}
		
		private static function Scan($RequestData = "", $PUBLIC_RSA_KEY = "")
		{
			try
			{
				if ($RequestData !== "")
				{
					$ParameterCount = 0;
					$PassedDetection = 0;
					$ScannedSafeData = '{';
					
					foreach($RequestData as $RequestKey => $RequestParameter)
					{
						if (Security::Analyze($RequestKey, $RequestParameter, $PUBLIC_RSA_KEY))
						{
							if ($ParameterCount !== 0)
								$ScannedSafeData .= ', ';
							$ScannedSafeData .= '"' . $RequestKey . '" : "' . $RequestParameter . '"';
							$PassedDetection++;
						}
						
						$ParameterCount++;
					}
					
					$ScannedSafeData .= '}';
					
					if ($PassedDetection === $ParameterCount)
					{
						return json_decode($ScannedSafeData, true); // Filtered/Safe (Re-created) Input Data.
					} else {
						return false;
					}
				} else {
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => -2, "message" => "No request was supplied to the NeatVibez firewall system."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					Logger::Log(Settings::$LogPrefix, "has refused the connection due to a missing supplied request");
					return false;
				}
			} catch(Exception $Exception)
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "An invalid request was supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				Logger::Log(Settings::$LogPrefix, "has refused the connection due to an invalid supplied request");
				return false;
			}
		}
		
		private static function Analyze($RequestKey, $RequestParameter = "", $PUBLIC_RSA_KEY = "") // Perhaps implement more analysis techniques including heuristics?
		{
			try
			{
				$Detections = 0;
				$Fails = 0;
				
				for ($Iteration = 0; $Iteration < count(Security::$MALICIOUS_INPUT); $Iteration++)
				{
					if ($RequestKey  !== "")
					{
						if ($RequestKey !== "")
						{
							if(Security::FilterInput($RequestKey, Security::$MALICIOUS_INPUT[$Iteration]) !== false) {
								$Detections++;
							}
						}
					} else {
						$Fails++;
					}
					
					if ($RequestParameter  !== "")
					{
						if ($RequestParameter !== "")
						{
							if(Security::FilterInput($RequestParameter, Security::$MALICIOUS_INPUT[$Iteration]) !== false) {
								$Detections++;
							}
						}
					} else {
						$Fails++;
					}
				}
				if ($Fails > 0)
				{
					if ($Detections === 0) // Needs a bit more work to reduce false positives over un-mandatory input data.
					{
						return true;
					} else {
						return false;
					}
				} else if ($Fails <= 0) {
					if ($Detections === 0)
					{
						return true;
					} else {
						return false;
					}
				}                                                                                                             
			} catch(Exception $Exception)
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "An invalid request parameter was supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				Logger::Log(Settings::$LogPrefix, "has refused the connection due to an invalid supplied request parameter");
				return false;
			}
		}
		
		private static function FilterInput($needle, $haystack)
		{
			if ($needle !== "")
			{
				if (strpos($haystack, $needle) !== false) {
					return true;
				}
			}
			return false;
		}
		
		public static function GenerateKeys()
		{
			// Configuration settings for the key
			$config = array(
				"digest_alg" => "sha512",
				"private_key_bits" => 4096,
				"private_key_type" => OPENSSL_KEYTYPE_RSA,
			);

			// Create the private and public key
			$res = openssl_pkey_new($config);

			// Extract the private key into $private_key
			openssl_pkey_export($res, $private_key);

			// Extract the public key into $public_key
			$public_key = openssl_pkey_get_details($res);
			$public_key = $public_key["key"];
			
			return ["private" => $private_key, "public" => $public_key];
		}

		public static function Encrypt($Message = "", $PUBLIC_KEY)
		{
			$publicKey = openssl_get_publickey($PUBLIC_KEY);
			
			// Encrypt using the public key
			openssl_public_encrypt($Message, $encrypted, $publicKey);
			$encrypted_hex = base64_encode($encrypted);
			
			return $encrypted_hex;
		}

		public static function Decrypt($Message = "", $USER_AGENT_PRIVATE_KEY = "")
		{
			if ($USER_AGENT_PRIVATE_KEY === "")
				$USER_AGENT_PRIVATE_KEY = Security::$PRIVATE_KEY;
			
			$privateKey = openssl_get_privatekey($USER_AGENT_PRIVATE_KEY);
			
			// Decrypt the data using the private key;
			openssl_private_decrypt(base64_decode($Message), $decrypted, $privateKey);

			return $decrypted;
		}
		
		public static function SignMessage($Message = "", $USER_AGENT_PRIVATE_KEY = "")
		{
			if ($USER_AGENT_PRIVATE_KEY === "")
				$USER_AGENT_PRIVATE_KEY = Security::$PRIVATE_KEY;
			
			$binary_signature = "";
			
			// Sign using the private key
			openssl_sign($Message, $binary_signature, $USER_AGENT_PRIVATE_KEY, OPENSSL_ALGO_SHA1);
			
			return base64_encode($binary_signature);
		}
		
		public static function VerifyMessage($Message = "", $Signature = "", $PUBLIC_KEY = "")
		{
			$publicKey = openssl_get_publickey($PUBLIC_KEY);
			$Signature = base64_decode($Signature);
			
			// Check signature
			$VerifySignature = openssl_verify($Message, $Signature, $publicKey, OPENSSL_ALGO_SHA1);
			
			if ($VerifySignature == 1) {
				return true;
			} elseif ($VerifySignature == 0) {
				return false;
			} else {
				return false;
			}
		}
	}
?>