<?php
	class Logger {
		public static $LogPrefix = "NeatVibez API" . " v" . "0.1.0" . " running on " . "NeatVibezPHP" . " v" . "0.0.7" . " authored by HashDoge";
		
		public static function Log($Referrer = "NeatVibez API", $Description = "")
		{
			try
			{
				if ($Description !== "")
				{
					file_put_contents('Logs/Log_'.date("j.n.Y").'.log', $Referrer . " - " . $Description . ".\n", FILE_APPEND);
				} else {
					file_put_contents('Logs/Log_'.date("j.n.Y").'.log', $Referrer . " has attempted to append a log with empty description.\n", FILE_APPEND);
				}
			} catch(Exception $Exception)
			{
				file_put_contents('Logs/Log_'.date("j.n.Y").'.log', $Referrer . " has attempted to append a log with empty description.\n", FILE_APPEND);
			}
		}
	}
?>