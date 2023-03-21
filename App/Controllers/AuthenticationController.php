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

	class AuthenticationController {
		
		protected $Client;
		protected $IP = "";
		protected $AuthCollection;
		
		protected $Token = "";
		protected $TokenData = [];
		
		protected $MentorKey = "";
		
		public function __construct($InputData, $ActionMethod, $Client, $IP = false, $PUBLIC_RSA_KEY = "")
		{
			if (isset($InputData["Action"]) && $InputData["Action"] !== "")
			{
				if ($IP !== false)
				{
					$this->IP = $IP;
				} else {
					Logger::Log(Settings::$LogPrefix, "has refused the connection due to a failure in acquiring IP Address");
					
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to a failure in acquiring IP Address."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				}
				
				switch($InputData["Action"])
				{
					case "AuthenticateToken" :
						if (isset($InputData["Token"]))
						{
							if ($InputData["Token"] !== "")
							{
								$this->Token = $InputData["Token"];
								$this->TokenData = Token::Decode($this->Token);
							}
						}
						break;
					case "AuthenticateMentorKey" :
						if (isset($InputData["MentorKey"]))
						{
							if ($InputData["MentorKey"] != "")
							{
								$this->MentorKey = $InputData["MentorKey"];
							}
						}
						break;
					default:
						break;
				}
			} else {
				Logger::Log(Settings::$LogPrefix, "has refused the connection due to an invalid supplied Action");
				
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to an invalid supplied Action."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
			
			if ($ActionMethod !== "")
			{
				$this->Client = $Client;
				
				if ($ActionMethod === "AuthenticateMentorKeyAction")
					$this->AuthCollection = $this->Client->ScholarFindr->MentorKeys;
			}
			else {
				return false;
			}
		}
		
		public function __destruct() {
			// Destroying class.
		}
		
		function AuthenticateTokenAction($PUBLIC_RSA_KEY)
		{
			if ($this->Token != "")
			{
				$RenewedToken = Token::Generate($this->TokenData["user"]["uid"], "", $this->Token, $this->TokenData["sequence"], $PUBLIC_RSA_KEY);
				
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 1, "message" => "Your API Token was renewed.", "token" => $RenewedToken], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			} else {
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "API Token must be supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
		}
		
		function AuthenticateMentorKeyAction($PUBLIC_RSA_KEY)
		{
			AuthenticationController::AuthenticateMentorKey($this->AuthCollection, $this->MentorKey, false, $PUBLIC_RSA_KEY);
		}
		
		static function AuthenticateMentorKey($AuthCollection = false, $MentorKey = false, $Registration = false, $PUBLIC_RSA_KEY = "")
		{
			$MentorKeyInfo = false;
			
			if ($MentorKey !== false && $AuthCollection !== false)
			{
				$MentorKeyInfo = $AuthCollection->findOne(["mentor_key" => $MentorKey]);
			}
			
			if (isset($MentorKeyInfo) && $MentorKeyInfo !== false && $MentorKeyInfo !== null)
			{
				if ($MentorKeyInfo->active === 0)
				{
					if ($Registration)
					{
						return $mentorKey;
					} else {
						$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 1, "message" => "Supplied Mentor Key is valid and ready to be redeemed."], true)), $PUBLIC_RSA_KEY);
						$ResponseSignature = Security::SignMessage($EncryptedResponse);
						
						return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					}
				} else {
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Supplied Mentor Key has already been used."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				}
			} else {
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Supplied Mentor Key is invalid."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
		}
		
		static function ActivateMentorKey($Client = false, $UID = false, $MentorKey = false, $PUBLIC_RSA_KEY = "")
		{
			if ($MentorKey !== false && $UID !== false)
			{	
				if (AuthenticationController::AuthenticateMentorKey($Client->ScholarFindr->MentorKeys, $MentorKey, true) !== false)
				{
					$ActivatedMentorKey = $Client->ScholarFindr->MentorKeys->updateOne(["mentor_key" => $MentorKey], ['$set' => ["uid" => $UID, "active" => 1, "active_date" => date("d/m/Y H:i:s")]]);
					
					if ($ActivatedMentorKey->getModifiedCount() > 0)
					{
						return true;
					} else {
						Logger::Log(Settings::$LogPrefix, "was unable to activate supplied Mentor Key");
						return false;
					}
				} else {
					return false;
				}
			} else {
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Mentor Key must be supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				return false;
			}
		}
	}
?>