<?php
	class AccountController {
		
		protected $Client;
		protected $IP = "";
		protected $AccountsCollection;
		
		protected $Token = "";
		protected $TokenData = [];
		
		protected $UID = "";
		protected $PWD = "";
		protected $FName = "";
		protected $MName = "";
		protected $LName = "";
		protected $MobileNo = "";
		protected $Email = "";
		protected $Gender = -1;
		protected $BDate = "";
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
					case "Login" :
						if (isset($InputData["UID"]) && $InputData["UID"] !== "")
						{
							$this->UID = htmlspecialchars(strip_tags($InputData["UID"]));
						}
						if (isset($InputData["PWD"]) && $InputData["PWD"] !== "")
						{
							//$this->PWD = Password::hash(htmlspecialchars(strip_tags($InputData["PWD"])), base64_encode(htmlspecialchars(strip_tags($InputData["UID"] . $InputData["PWD"]))));
							$this->PWD = htmlspecialchars(strip_tags($InputData["PWD"]));
						}
						if (isset($InputData["Token"]))
						{
							if ($InputData["Token"] !== "")
							{
								$this->Token = $InputData["Token"];
								$this->TokenData = Token::Decode($this->Token);
							}
						}
						break;
					case "Register" :
						if (isset($InputData["UID"]) && $InputData["UID"] !== "")
						{
							$this->UID = htmlspecialchars(strip_tags($InputData["UID"]));
						}
						if (isset($InputData["PWD"]) && $InputData["PWD"] !== "")
						{
							$this->PWD = Password::hash(htmlspecialchars(strip_tags($InputData["PWD"])), base64_encode(htmlspecialchars(strip_tags($InputData["UID"] . $InputData["PWD"]))));
						}
						if (isset($InputData["FName"]) && $InputData["FName"] !== "")
						{
							$this->FName = htmlspecialchars(strip_tags($InputData["FName"]));
						}
						if (isset($InputData["MName"]) && $InputData["MName"] !== "")
						{
							$this->MName = htmlspecialchars(strip_tags($InputData["MName"]));
						}
						if (isset($InputData["LName"]) && $InputData["LName"] !== "")
						{
							$this->LName = htmlspecialchars(strip_tags($InputData["LName"]));
						}
						if (isset($InputData["MobileNo"]) && $InputData["MobileNo"] !== "")
						{
							$this->MobileNo = htmlspecialchars(strip_tags($InputData["MobileNo"]));
						}
						if (isset($InputData["Email"]) && $InputData["Email"] !== "")
						{
							$this->Email = htmlspecialchars(strip_tags($InputData["Email"]));
						}
						if (isset($InputData["Gender"]) && $InputData["Gender"] !== -1)
						{
							$this->Gender = htmlspecialchars(strip_tags($InputData["Gender"]));
						}
						if (isset($InputData["BDate"]) && $InputData["BDate"] !== "")
						{
							$this->BDate = htmlspecialchars(strip_tags($InputData["BDate"]));
						}
						if (isset($InputData["MentorKey"]) && $InputData["MentorKey"] !== "")
						{
							$this->MentorKey = htmlspecialchars(strip_tags($InputData["MentorKey"]));
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
				$this->AccountsCollection = $this->Client->ScholarFindr->Accounts;
			}
		}
		
		public function __destruct() {
			// Destroying class.
		}
		
		function LoginAction($PUBLIC_RSA_KEY)
		{
			if ($this->UID != "")
			{
				if ($this->PWD != "")
				{
					$AccountInfo = $this->AccountsCollection->findOne(["uid" => $this->UID]);
					if (isset($AccountInfo) && $AccountInfo !== null)
					{
						if ($AccountInfo->uid == $this->UID && Password::check($this->PWD, $AccountInfo->pwd))
						{
							$Sequence = 0;
							if (isset($this->Token) && $this->Token !== "")
							{
								if (isset($this->TokenData["sequence"]) && $this->TokenData["sequence"] > 0)
								{
									$Sequence = $this->TokenData["sequence"];
								}
							}
							
							$this->Token = Token::Generate($AccountInfo->uid, "", $this->Token, $Sequence, $PUBLIC_RSA_KEY);
							
							if ($this->Token !== false)
							{
								$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 1, "message" => "You have successfully logged in.", "token" => $this->Token], true)), $PUBLIC_RSA_KEY);
								$ResponseSignature = Security::SignMessage($EncryptedResponse);
								
								return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
							} else {
								Logger::Log(Settings::$LogPrefix. "has refused the connection due to a failure in renewing the token");
								
								$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Failed to generate API Token."], true)), $PUBLIC_RSA_KEY);
								$ResponseSignature = Security::SignMessage($EncryptedResponse);
								
								return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
							}
						} else {
							$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Account credentials combination is incorrect."], true)), $PUBLIC_RSA_KEY);
							$ResponseSignature = Security::SignMessage($EncryptedResponse);
							
							return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
						}
					} else {
						$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Account credentials combination is incorrect."], true)), $PUBLIC_RSA_KEY);
						$ResponseSignature = Security::SignMessage($EncryptedResponse);
						
						return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					}
				} else {
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Account Password must be supplied."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				}
			} else {
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Account Username must be supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
		}
		
		function RegisterAction($PUBLIC_RSA_KEY)
		{
			if ($this->UID != "")
			{
				$Lookup = $this->AccountsCollection->findOne(["uid" => $this->UID]);
				if (isset($Lookup) && $Lookup !== null)
				{
					if ($Lookup->uid == $this->UID)
					{
						$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Username already exists."], true)), $PUBLIC_RSA_KEY);
						$ResponseSignature = Security::SignMessage($EncryptedResponse);
						
						return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					}
				}
			} else {
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Username must be supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
			
			if ($this->PWD == "")
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Password must be supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
			
			if ($this->FName == "")
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "First Name must be supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
			
			if ($this->LName == "")
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Last Name must be supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
			
			if ($this->MobileNo != "")
			{
				$Lookup = $this->AccountsCollection->findOne(["mobileno" => $this->MobileNo]);
				if (isset($Lookup) && $Lookup !== null)
				{
					if ($Lookup->mobileno == $this->MobileNo)
					{
						$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Mobile Number already exists."], true)), $PUBLIC_RSA_KEY);
						$ResponseSignature = Security::SignMessage($EncryptedResponse);
						
						return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					}
				}
			} else {
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Mobile Number must be supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
			
			if ($this->Email != "")
			{
				if (filter_var($this->Email, FILTER_SANITIZE_EMAIL))
				{
					$Lookup = $this->AccountsCollection->findOne(["email" => $this->Email]);
					if (isset($Lookup) && $Lookup !== null)
					{
						if ($Lookup->email == $this->Email)
						{
							$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "E-mail Address already exists."], true)), $PUBLIC_RSA_KEY);
							$ResponseSignature = Security::SignMessage($EncryptedResponse);
							
							return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
						}
					}
				} else {
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Provided E-mail Address is not valid."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				}
			} else {
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "E-mail Address must be supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
			
			if ($this->Gender < 0)
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Gender must be supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
			
			if ($this->BDate == "")
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Birth Date must be supplied."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
			
			if ($this->MentorKey !== "")
			{
				if (AuthenticationController::ActivateMentorKey($this->Client, $this->UID, $this->MentorKey, $PUBLIC_RSA_KEY) === false)
				{
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Mentor Key is invalid."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				}
			}
			
			$InsertedAccount = $this->AccountsCollection->InsertOne(["uid" => $this->UID, "pwd" => $this->PWD, "fname" => $this->FName, "mname" => $this->MName, "lname" => $this->LName, "mobileno" => $this->MobileNo, "email" => $this->Email, "gender" => $this->Gender, "bdate" => $this->BDate, "mentorkey" => $this->MentorKey, "status" => 1]);
			
			if ($InsertedAccount->getInsertedId() != "")
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 1, "message" => "Registration was successful", "user" => $InsertedAccount->getInsertedId()], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			} else {
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "Registration failed."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
		}
	}
?>