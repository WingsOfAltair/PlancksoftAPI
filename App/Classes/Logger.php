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

use Psr\Log\LoggerInterface;

class Logger implements LoggerInterface 
{
    private const API_VERSION = '0.2.0';
    private const API_NAME = 'NeatVibez API';
    private const LIBRARY_VERSION = '0.0.8';
    private const AUTHOR_NAME = 'WingsOfAltair';

    private $logFilePath;

    public function __construct(string $logFilePath) 
    {
        if (!is_writable($logFilePath)) {
            throw new InvalidArgumentException('Invalid log file path: ' . $logFilePath);
        }

        $this->logFilePath = $logFilePath;
    }

    public function emergency($message, array $context = array()) 
    {
        $this->log('emergency', $message, $context);
    }

    public function alert($message, array $context = array()) 
    {
        $this->log('alert', $message, $context);
    }

    public function critical($message, array $context = array()) 
    {
        $this->log('critical', $message, $context);
    }

    public function error($message, array $context = array()) 
    {
        $this->log('error', $message, $context);
    }

    public function warning($message, array $context = array()) 
    {
        $this->log('warning', $message, $context);
    }

    public function notice($message, array $context = array()) 
    {
        $this->log('notice', $message, $context);
    }

    public function info($message, array $context = array()) 
    {
        $this->log('info', $message, $context);
    }

    public function debug($message, array $context = array()) 
    {
        $this->log('debug', $message, $context);
    }

    public function log($level, $message, array $context = array()) 
    {
        $logMessage = self::API_NAME . ' v' . self::API_VERSION . ' running on NeatVibezPHP v' . self::LIBRARY_VERSION . ' authored by ' . self::AUTHOR_NAME;
        $logMessage .= ' - ' . $this->interpolate($message, $context) . ' [' . strtoupper($level) . ']';

        try {
            file_put_contents($this->logFilePath, $logMessage . PHP_EOL, FILE_APPEND);
        } catch (\Throwable $exception) {
            error_log($exception->getMessage());
        }
    }

    private function interpolate($message, array $context = array()) 
    {
        $replace = array();
        foreach ($context as $key => $val) {
            $replace['{' . $key . '}'] = $val;
        }

        return strtr($message, $replace);
    }
}

?>
