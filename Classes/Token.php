<?php
	class Token {
		public static function Validate($Token = "", $PUBLIC_RSA_KEY = "")
		{
			try
			{
				if ($Token !== "")
				{
					$DecodedToken = Token::Decode($Token);
					$TokenDate = date($DecodedToken["timestamp"]);
					$ValidTimeRange = new DateTime("- 8 minutes");
					$ValidTimeRange = $ValidTimeRange->format("d/m/Y H:i:s");
					
					if ($TokenDate !== "")
					{
						if ($TokenDate >= $ValidTimeRange)
						{
							return Token::Verify($DecodedToken, $Token, $PUBLIC_RSA_KEY);
						} else {
							$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Supplied API Token has expired, and/or could be invalid."], true)), $PUBLIC_RSA_KEY);
							$ResponseSignature = Security::SignMessage($EncryptedResponse);
							
							echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
							die();
						}
					} else {
						$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "An invalid API Token was supplied."], true)), $PUBLIC_RSA_KEY);
						$ResponseSignature = Security::SignMessage($EncryptedResponse);
						
						echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
						Logger::Log(Settings::$LogPrefix, "has refused the connection due to an invalid supplied API Token");
						die();
					}
				} else {
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "API Token must be supplied."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					Logger::Log(Settings::$LogPrefix, "has refused the connection due to a missing API Token");
					die();
				}
			} catch(Exception $Exception)
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "An invalid API Token was supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				Logger::Log(Settings::$LogPrefix, "has refused the connection due to an invalid supplied API Token");
				die();
			}
		}
		
		private static function Verify($DecodedToken = "", $Token = "", $PUBLIC_RSA_KEY = "")
		{
			try
			{
				if ($Token !== "")
				{	
					$Client = new MongoDB\Client;
					
					if ($UID = $DecodedToken["user"]["uid"])
					{
						$AuthInfo = $Client->ScholarFindr->Auth->findOne(["token" => $Token, "uid" => $UID, "ipv4" => $DecodedToken["ipv4"]]);
						if (isset($AuthInfo) && $AuthInfo !== null)
						{
							return $AuthInfo->token;
						} else {
							$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Your supplied API Token is invalid."], true)), $PUBLIC_RSA_KEY);
							$ResponseSignature = Security::SignMessage($EncryptedResponse);
							
							echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
							Logger::Log(Settings::$LogPrefix, "has refused the connection due to an invalid supplied API Token");
							die();
						}
					} else {
						$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Your supplied API Token is invalid."], true)), $PUBLIC_RSA_KEY);
						$ResponseSignature = Security::SignMessage($EncryptedResponse);
						
						echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
						Logger::Log(Settings::$LogPrefix, "has refused the connection due to an invalid supplied API Token");
						die();
					}
				} else {
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "API Token must be supplied."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					Logger::Log(Settings::$LogPrefix, "has refused the connection due to a missing API Token");
					die();
				}
			} catch(Exception $Exception)
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "An invalid API Token was supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				Logger::Log(Settings::$LogPrefix, "has refused the connection due to an invalid supplied API Token");
				die();
			}
		}
		
		public static function Generate($UID = "", $Time = "", $Token = "", $Sequence = 0, $PUBLIC_RSA_KEY = "")
		{
			if ($Time === ""){
				$Time = new DateTime("now");
				$Time = $Time->format("d/m/Y H:i:s");
			}
			
			if ($UID !== "")
			{
				$Client = new MongoDB\Client;
				
				$GeneratedToken = "NeatVibez " . base64_encode(serialize(json_decode(json_encode(["user" => ["uid" => $UID], "ipv4" => $_SERVER['REMOTE_ADDR'], "timestamp" => $Time, "sequence" => ($Sequence + 1)], true), true)));
				
				if ($Sequence === 0)
				{
					$InsertedToken = $Client->ScholarFindr->Auth->InsertOne(["uid" => $UID, "token" => $GeneratedToken, "ipv4" => $_SERVER['REMOTE_ADDR'], "entrydate" => $Time]);
						
					if ($InsertedToken->getInsertedId() != "")
					{
						return $GeneratedToken;
					} else {
						$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Failed to generate API Token."], true)), $PUBLIC_RSA_KEY);
						$ResponseSignature = Security::SignMessage($EncryptedResponse);
						
						echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
						Logger::Log(Settings::$LogPrefix, "has refused the connection due to a failure generating an API Token");
						return false;
					}
				} else {
				$UpdatedToken = $Client->ScholarFindr->Auth->updateOne(["uid" => $UID, "token" => $Token], ['$set' => ["token" => $GeneratedToken, "ipv4" => $_SERVER['REMOTE_ADDR'], "entrydate" => $Time]]);
					
					if ($UpdatedToken->getModifiedCount() > 0)
					{
						return $GeneratedToken;
					} else {
						$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Failed to generate a new API Token."], true)), $PUBLIC_RSA_KEY);
						$ResponseSignature = Security::SignMessage($EncryptedResponse);
						
						echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
						Logger::Log(Settings::$LogPrefix, "has refused the connection due to a failure generating a new API Token");
						die();
					}
				}
			}
			else
			{
				return false;
			}
		}
		
		public static function Decode($Token = "")
		{
			try
			{
				if ($Token !== "")
				{
					$Token = Token::StripToken($Token);
					
					if ($Token !== false)
					{
						return json_decode(json_encode(unserialize(base64_decode($Token)), true), true);
					}
					else
					{
						return false;
					}
				}
			} catch (Exception $Exception)
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Failed to acquire API Token information."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				Logger::Log(Settings::$LogPrefix, "has refused the connection due to a failure in acquiring supplied API Token information");
				return false;
			}
		}
		
		public static function StripToken($Token = "")
		{
			try
			{
				if (isset($Token))
				{
					if ($Token !== "")
					{
						list($Signature, $StrippedToken) = explode(' ', $Token);
						
						if ($Signature === "NeatVibez")
						{
							$Token = Security::Decrypt($Token);
							if ($Token !== "")
							{
								return $StrippedToken;
							} else {
								$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Failed to decrypt API Token."], true)), $PUBLIC_RSA_KEY);
								$ResponseSignature = Security::SignMessage($EncryptedResponse);
								
								echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
								Logger::Log(Settings::$LogPrefix, "has refused the connection due to a failure in decrypting supplied API Token");
								die();
							}
						}
						else
						{
							$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Failed to morph API Token."], true)), $PUBLIC_RSA_KEY);
							$ResponseSignature = Security::SignMessage($EncryptedResponse);
							
							echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
							Logger::Log(Settings::$LogPrefix, "has refused the connection due to a failure in morphing supplied API Token");
							die();
						}
					} else {
						$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Failed to morph API Token."], true)), $PUBLIC_RSA_KEY);
						$ResponseSignature = Security::SignMessage($EncryptedResponse);
						
						echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
						Logger::Log(Settings::$LogPrefix, "has refused the connection due to a failure in morphing supplied API Token");
						die();
					}
				}
			} catch (Exception $Exception)
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Failed to morph API Token."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				Logger::Log(Settings::$LogPrefix, "has refused the connection due to a failure in morphing supplied API Token");
				die();
			}
		}
	}
?>