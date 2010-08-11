<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * WiKID Strong Authentication module for PHP
 *
 * http://sourceforge.net/projects/wikid-twofactor/
 *
 * This is the core SSL client for WiKID Authentication.  wClient manages
 * communication between Network Clients (NC) and the WiKID Authentication
 * Server (wAuth).
 *
 * Other versions of wClient support persistance of the SSL socket connection

 * to improve the performance of the communications, by avoiding the overhead
 * of the SSL and RSA key generation and negotiation.  However, because PHP
 * does not currently support persistance of socket handles, via $_SESSION or
 * any other means, we must incur this overhead on each connection to the
 * wAuth server.
 *
 * Auth_WiKID and wClient refer to the same module.
 *
 * Requires PHP >= 4.3.2, for ssl socket communications.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: Lesser GNU Public License
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @category    Authentication
 * @package     Auth_WiKID
 * @author      Greg Haygood <ghaygood@wikidsystems.com>
 * @copyright   2001-2005 WiKID Systems, Inc.  All rights reserved.
 * @license     http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version     CVS: $Id: wClient.inc.php,v 1.10 2005/11/06 00:38:28 ghaygood Exp $
 * @link        http://pear.php.net/package/Auth_WiKID
 *
 */
/**
 * wClient is the object through which a PHP programmer can communicate
 * with a wAuth server.
 *
 * @category    Authentication
 * @package     Auth_WiKID
 * @author      Greg Haygood <ghaygood@wikidsystems.com>
 * @copyright   2001-2005 WiKID Systems, Inc.  All rights reserved.
 * @license     LGPL http://www.gnu.org/copyleft/lesser.html
 * @version     Release: @package_version@
 * @link        http://pear.php.net/package/Auth_WiKID
 *
 */
class wClient
{
    /**
     * The socket handle
     *
     * @var resource
     * @access private
     */
    var $_socket;

    /**
     * Indicates whether the socket handle is active
     *
     * @var boolean
     * @access private
     */
    var $_isConnected = false;

    /**
     * Path to PEM-encoded certificate+key file for client certificate
     * authentication with wAuth
     *
     * @var string
     * @access private
     */
    var $_keyfile;

    /**
     * Passphrase for {@link $_keyfile}
     *
     * @var string
     * @access private
     */
    var $_keypass;

    /**
     * IP address or hostname to wAuth server
     *
     * @var string
     * @access private
     */
    var $_host;

    /**
     * TCP port of wAuth {@link $_host}
     *
     * @var int
     * @access private
     */
    var $_port = 8388;

    /**
     * Path to PEM-encoded CA certificate for wAuth communication validation
     *
     * @var string
     * @access private
     */
    var $_cafile = "/opt/WiKID/private/WiKIDCA.cer";

    /**
     * Idle time to allow before closing socket, and time limit on socket open attempt
     *
     * @var int
     * @access private
     */
    var $_timeout = 30;

    /**
     * Controls whether debug messages will be printed
     *
     * @var boolean
     * @access private
     */
    var $_DEBUG = false;

    /**
     * This constructor allows the wClient module to be initialized from
     * either a properties file or via explicit arguments.
     *
     * @param string $host_or_file   Either the IP address or hostname of
     *                               the wAuth server, or the path to a
     *                               properties file
     * @param int $port              The SSL listener port for the wAuth
     *                               daemon on the wAuth server
     * @param string $keyfile        The PKCS12 keystore generated for this
     *                               client by the wAuth server
     * @param string $pass           The passphrase securing the keys in keyfile
     * @param string $cafile         The certificate authority store for
     *                               validating the wAuth server certificate
     *
     * The contents of the propertiesfile should contain the following
     * key-value pairs:
     * <ul>
     *   <li> host - The IP address or hostname of the wAuth server
     *   <li> port - The SSL listener port for the wAuth daemon on the
     *               wAuth server
     *   <li> keyfile - The PKCS12 keystore generated for $this->client by
     *               the wAuth server
     *   <li> pass - The passphrase securing the keys in keyfile
     *   <li> cafile - The PEM-encoded certificate file for validating the wAuth
     *                  server certificate
     * </ul>
     */
    function wClient($host_or_file, $port = 0, $keyfile = '', $keypass = '',
                     $cafile = '')
    {
        $min_version = "4.3.2";
        if (version_compare($min_version, phpversion(), ">=")) {

            echo "Incompatible version - wClient requires PHP >= $min_version\n";
            return null;
        }

        if (is_file($host_or_file)) {
            $props = parse_ini_file($host_or_file);

            $this->_host = $props['host'];
            $this->_port = $props['port'];
            $this->_keyfile = $props['keyfile'];
            $this->_keypass = $props['pass'];
            $this->_cafile = $props['cafile'];
        } else {
            $this->_host = $host_or_file;
            $this->_port = $port;
            $this->_keyfile = $keyfile;
            $this->_keypass = $keypass;
            if (!empty($cafile)) {
                $this->_cafile = $cafile;
            }
        }
        if (!is_numeric($this->_port)) { $this->_port = 0; }

        $this->_init();
        return true;
    }

    /**
     * Class destructor, which just calls close().
     *
     * @access public
     */
    function __destroy()
    {
        $this->close();
    }

    /**
     * This method simply closes the connection to the wAuth.
     *
     * @access public
     */
    function close()
    {
        $this->_dprint("Closing wClient connection ...");
        if ($this->isConnected()) {
            fwrite($this->_socket, "QUIT\n");
            fflush($this->_socket);
            fclose($this->_socket);
        }
        $this->_isConnected = false;
    }

    /**
     * This method checks that the certificates are readable.
     *
     * @access private
     */
    function _init()
    {
        set_time_limit($this->_timeout);

        $ca = openssl_pkey_get_public("file://".$this->_cafile);
        if (!$ca) {
            echo "CA Public key NOT OK! " ;
            //$this->_dprint("CA Public key NOT OK!");
        } else {
            $this->_dprint("CA Public Key OK. ");
        }
        $pub = openssl_pkey_get_public("file://".$this->_keyfile);
        if (!$pub) {
            echo "Public key NOT OK! ";
            //$this->_dprint("Public key NOT OK!");
        } else {
            $this->_dprint("Public Key OK. ");
        }
        $priv = openssl_pkey_get_private("file://$this->_keyfile", $this->_keypass);
        if (!$priv) {
            echo "Private key NOT OK! ";
            //$this->_dprint("Private key NOT OK!");
        } else {
            $this->_dprint("Private Key OK. ");
        }
    }

		function send($mesg)
		{
			$mesg = str_replace("\n", "", $mesg);
			echo ("send.request is:");
			print_r($mesg);
			echo "-----------";
			$response = $this->_request($mesg);
			echo ("send.response is:");
			print_r($response);
			if ($response) {
				$xml = new SimpleXMLElement($response);
				print_r($xml);
			} else {
				$resp = "No response received!";
				$this->_dprint($resp);
			}
			return $xml;
		}

		function _ping()
		{
				$send = '<transaction> <type>1</type> <data> <value>TX</value> </data> </transaction>';
				$xml = $this->send($send);
		}

		function _request($mesg)
		{
			$response = '';
			if ($this->_socket) {
				$this->_dprint("sending string '$mesg' ...");
				fwrite($this->_socket, $mesg . "\n");
				fflush($this->_socket);

				if (!feof($this->_socket)) {
						$this->_dprint("checking response...");
						$response = fgets($this->_socket);
				}
			} else {
				$this->_dprint("closing connection ...");
				$this->_isConnected = false;
				echo("Error reading from server.\n");
			}
			return $response;
		}

    /**
     * This method reconnects to the wAuth server, if the socket handle is dead.
     *
     * @return boolean              Whether the socket is connected
     * @access private
     */
    function reconnect()
    {
        $this->_dprint("Reconnect Called.");
        $this->_dprint("\$this->_isConnected: " . $this->_isConnected);
        $status = @socket_get_status($this->_socket);
        if ($this->_DEBUG) {
            $this->_dprint("reconnect(): Socket Status:");
            print_r($status);
        }

        if  (!$this->_isConnected || $status['timed_out']) {
            $this->_dprint("Socket dead.  Reconnecting...");

            if ($this->_DEBUG) {
                if (function_exists("stream_get_wrappers")) {
                    $this->_dprint("Available Stream Wrappers:");
                    print_r(stream_get_wrappers());
                    print "<br>\n";
                }
                if (function_exists("stream_get_transports")) {
                    $this->_dprint("Available Stream Transports:");
                    print_r(stream_get_transports());
                    print "<br>\n";
                }
                $this->_dprint("Default Context Options:");
                print_r(stream_context_get_options($context));
                print "<br>\n";
            }
            $this->_dprint("Setting context ...");
            $socket_opts = array(
                'ssl' => array(
                    'local_cert'             => $this->_keyfile,
                    'passphrase'             => $this->_keypass,
                    'verify_peer'            => false,
                    'allow_self_signed'      => false,
                )
            );
            if (openssl_pkey_get_public("file://".$this->_cafile)) {
                $socket_opts['ssl']['cafile'] = $this->_cafile;
                $socket_opts['ssl']['verify_peer'] = true;
            }
            $context = stream_context_create($socket_opts);
            if ($this->_DEBUG) {
                $this->_dprint("Configured Context Options:");
                print_r(stream_context_get_options($context));
                print "<br>\n";
            }
            #stream_set_blocking($this->_socket, 0);
            #stream_set_timeout($this->_socket, $this->_timeout);
            $this->_dprint("Opening socket ...");
            if (function_exists("stream_socket_client")) {
                $this->_socket = stream_socket_client("tls://".$this->_host.":".$this->_port,
                                            $errno, $errstr, $this->_timeout,
                                            STREAM_CLIENT_CONNECT, $context);
            } else {
                $this->_socket = fsockopen("tls://".$this->_host, $this->_port,
                                            $errno, $errstr, $this->_timeout,
                                            $context);
            }
            $this->_dprint("Socket handle: '$this->socket'");
//			$this->_ping();
            if (!$this->_socket) {
                echo "Unable to reconnect: $errstr ($errno)<br/>\n";
                echo $this->_socket;
            } else {
                $this->_dprint("Connected!");
                $this->_isConnected = $this->_startConnection();
                $this->_dprint("Connection started ...");
            }
        }
        return $this->_isConnected;
    }

    /**
     * This method initiates the connection to the wAuth server.
     *
     * @return boolean              Whether the socket is connected
     * @access private
     */
    function _startConnection()
    {
        $this->_dprint("startConnection() Called.");
        $valid_tag = "ACCEPT";
        // The client initiates the transaction
        $send = "CONNECT:0: wClientConnPHP $this->version";
				$send = '<transaction> <type>1</type> <data> <client-string>wClient PHP 3.0</client-string> <server-string>null</server-string> <result>null</result> </data> </transaction>
';
				$xml = $this->send($send);
				$result = $xml->data->result;
				if ($result == "ACCEPT") {
					$this->_dprint("wClient connection ACCEPTED");
					$this->_isConnected = true;
				} else {
					$this->_isConnected = false;
					$this->_dprint("wClient connection FAILED");
				}
        $this->_dprint("isConnected?: $this->_isConnected");
        return $this->_isConnected;
    }

    /**
     * Is the socket connected?
     *
     * @return boolean              Status of handle: true indicates connection is active
     * @access public
     */
    function isConnected()
    {
        return $this->_isConnected;
    }

    /**
     * Creates an association between the userid and the device registered
     * by the user.
     *
     * @param string $uname         Users login ID in this authentication domain
     * @param string $regcode       Registration code provided to user when
     *                               setting up this domain on users device
     * @param string $domaincode    12 digit code representing this
     *                               authentication domain
     * @param string $passcode      Optional passcode provided by the user, to
     *                               link this device to an existing registration
     * @return int                  Result code from the registration attempt
     *
     * @access public
     */
    function registerUsername($username, $regcode, $domaincode, $passcode = '')
    {
        $this->_dprint("registerUsername() called ...");
        $this->reconnect();
        $valid_tag = "REGUSER:SUCESS";
        if (isset($passcode) && strlen($passcode) > 0) {
            $this->_dprint("Adding new device ...");
            $command = "ADDREGUSER";
						$type = 5;
						$passcodeline = "<passcode>$passcode</passcode>";
						$format = "add";
        } else {
            $this->_dprint("Registering user ...");
            $command = "REGUSER";
						$type = 4;
						$passcodeline = "";
						$format = "new";
        }

        #$send = "$command:" . $uname . "\t" . $regcode . "\t" . $domaincode . "\t" . $passcode;
				$send = <<<XML
<transaction>
	<type format="$format">$type</type>
	<data>
	<user-id>$username</user-id>
	<registration-code>$regcode</registration-code>
	<domaincode>$domaincode</domaincode>
	$passcodeline
	<error-code>null</error-code>
	<result>null</result>
	</data>
</transaction>
XML;

				$xml = $this->send($send);
				$result = $xml->data->result;

				$this->_dprint("result: '$result'");
				echo "Result: $result";
				if ($result == "SUCCESS" || $result == "SUCESS") {
						$validCredentials = true;
						return 0;
				} else {
						$validCredentials = false;
						return $xml->data->{'error-code'};
				}
    }

    /**
     * Verifies credentials generated using the online mechanism.
     *
     * @param string $user          Users login ID in this authentication domain
     * @param string $passcode      Passcode provided by the user
     * @param string $domaincode    12 digit code representing the
     *                               authentication domain
     * @return boolean              'true' indicates credentials were valid,
     *                               'false' if credentials were invalid or
     *                               an error occurred
     * @access public
     */
    function checkCredentials($user, $passcode, $domaincode = '127000000001')
    {
        $this->_dprint("checkCredentials() called ...");

        $this->reconnect();
        $validCredentials = false;
        $this->_dprint("Checking Credentials...");

				$send = <<<XML
<transaction>
	<type format="base">2</type>
	<data>
		<user-id>$user</user-id>
		<passcode>$passcode</passcode>
		<domaincode>$domaincode</domaincode>
		<offline-challenge encoding="none">$offline_challenge</offline-challenge>
		<offline-response encoding="none">$offline_response</offline-response>
		<chap-password encoding="none">$chap_password</chap-password>
		<chap-challenge encoding="none">$chap_challenge</chap-challenge>
		<result>null</result>
	</data>
</transaction>
XML;

				$xml = $this->send($send);
				$result = $xml->data->result;

				$this->_dprint("result: '$result'");
				if ($result == "VALID") {
						$validCredentials = true;
				} else {
						$validCredentials = false;
				}
				$this->_dprint("Read response: verdict = " + $validCredentials);
        return $validCredentials;
    }

    /**
     * Verifies the credentials via challenge-response.
     *
     * <b>!!! Not currently supported by the Open Source release of WiKID.</b>
     *
     * @ignore
     * @return boolean              'true' indicates credentials were valid,
     *                               'false' if credentials were invalid or
     *                               an error occurred
     */
    function chapVerify($user, $domaincode, $wikidChallenge = '',
                        $chapPassword = '', $chapChallenge = '')
    {
        $this->_dprint("chapVerify() called ...");
        $this->reconnect();
        $validCredentials = false;
        $valid_tag = "VERIFY:VALID";
        $this->_dprint("Checking Chap Credentials");

        $send = "CHAPOFFVERIFY:" . $user . "\t" . "null" . "\t" .
                $domaincode . "\t" . $wikidChallenge;
        fflush($this->_socket);
        if ($this->_socket)
        {
            fwrite($this->_socket, strlen(chapPassword) . "\n");
            fwrite($this->_socket, chapPassword . "\n");
            fwrite($this->_socket, strlen(chapChallenge) . "\n");
            fwrite($this->_socket, chapChallenge . "\n");
            fflush($this->_socket);

            if (!feof($this->_socket)) {
                $this->_dprint("Reading in...");

                $inputLine = fgets($this->_socket);
                if (substr($inputLine, 0, strlen($valid_tag)) == $valid_tag) {
                    $validCredentials = true;
                }
            }
        }
        else
        {
            $this->_isConnected = false;
            echo("Error reading from server.\n");
        }

        return $validCredentials;
    }

    /**
     * Fetches a list of domains served by the currently connected server code.
     *
     * <b>!!! Not currently supported by the Open Source release of WiKID.</b>
     *
     *
     * @ignore
     * @return boolean              'true' indicates credentials were valid,
     *                               'false' if credentials were invalid or
     *                               an error occurred
     */
    function getDomains()
    {
        $this->_dprint("Getting domains ...");
        $this->reconnect();

				$send = <<<XML
<transaction>
	<type>3</type>
	<data>
		<domain-list>null</domain-list>
	</data>
</transaction>
XML;

				$xml = $this->send($send);
				$domains = $xml->data->{"domain-list"}->domain;

        return $domains;
    }

    /**
     * Prints a time-stamped (since the epoch) message if $__DEBUG is true.
     *
     * @param string $str           Message to print out
     * @access private
     */
    function _dprint($str)
    {
        if ($this->_DEBUG) {
            echo time() . ": $str<br />\n";
            flush();
        }
        return true;
    }
}
?>
