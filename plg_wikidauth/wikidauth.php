<?php
/**
 * @package WikidAuth for Joomla! 1.5
 * @author Jason Kendall
 * @copyright (C) 2010 - OSTLabs Inc
 * @license GNU/GPL http://www.gnu.org/copyleft/gpl.html
**/

// Check to ensure this file is included in Joomla!
defined('_JEXEC') or die( 'Restricted access' );

jimport( 'joomla.plugin.plugin' );


class plgAuthenticationWikidAuth extends JPlugin
{

	var $wc; // Holds the Wikied Auth Object
	var $domaincode; // Holds the domaincode from the init

	/**
	 * Constructor
	 *
	 * For php4 compatability we must not use the __constructor as a constructor for plugins
	 * because func_get_args ( void ) returns a copy of all passed arguments NOT references.
	 * This causes problems with cross-referencing necessary for the observer design pattern.
	 *
	 * @param object $subject The object to observe
	 * @param 	array  $config  An array that holds the plugin configuration
	 * @since 1.5
	 */
	function plgAuthenticationWikidAuth(& $subject, $config) {
		// Include the required LIB files
		require_once(dirname(__FILE__).DS.'wikidlib'.DS.'wClient.inc.php');

		parent::__construct($subject, $config);

		$server_host = $this->params->get('server_host');
		$server_port = $this->params->get('server_port');
		$client_key_file = $this->params->get('client_key_file');
		$client_key_pass = $this->params->get('client_key_pass');
//		$server_ca_file = $this->params->get('server_ca_file');

		$this->domaincode = $this->params->get('domaincode');

		$this->wc = new wClient($server_host, $server_port, $client_key_file, $client_key_pass); //, $server_ca_file);

	}

	/**
	 * This method should handle any authentication and report back to the subject
	 *
	 * @access	public
	 * @param   array 	$credentials Array holding the user credentials
	 * @param 	array   $options     Array of extra options
	 * @param	object	$response	Authentication response object
	 * @return	boolean
	 * @since 1.5
	 */
	function onAuthenticate( $credentials, $options, &$response )
	{

	    // Do the authentication
	    $success = $this->wc->checkCredentials($credentials['username'], $credentials['password'], $this->domaincode);

            if ($success == 0)
            {
                    $response->status            = JAUTHENTICATE_STATUS_SUCCESS;
                    $response->error_message = '';
//                    $response->email        = $credentials['username'];
//                    $response->fullname = $credentials['username'];
            }
            else
            {
                    $response->status               = JAUTHENTICATE_STATUS_FAILURE;
                    $response->error_message        = 'Failed to authenticate: ' . $message;
            }

//	    print_r($this); die();

	}

	function register($username, $regcode)
	{
    	    return  $this->wc->registerUsername($username, $regcode, $this->domaincode);

	}
}
