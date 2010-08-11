<?php
// Check to ensure this file is included in Joomla!
defined('_JEXEC') or die( 'Restricted access' );

jimport( 'joomla.application.component.controller' );

class WikidAuthController extends JController
{
    // Register Token
    function display()
    {
	$user =& JFactory::getUser(); 

	if ( $user->get('id') == 0 ) {
	    // You must be logged in!
	    return JError::raiseWarning('SOME_ERROR_CODE', JText::_('You must be logged in to use this function.'));
	}

	?>
	<script language="javascript" type="text/javascript">                                                                                                                                                                                                      
	<!--                                                                                                                                                                                                                                                       
            function submitbutton(pressbutton) {                                                                                                                                                                                                               
	        var form = document.usereditForm;                                                                                                                                                                                                              
                                                                                                                                                                                                                                                           
                // do field validation                                                                                                                                                                                                                         
        	form.submit();                                                                                                                                                                                                                                 
    	    }                                                                                                                                                                                                                                                  
	-->                                                                                                                                                                                                                                                        
	</script>
	<?

	echo "Please enter the registration code provided when adding a domain on your soft token.<BR /> <BR />";
	echo "<form action='" . JURI::base() . "index.php' name='usereditForm' method='post'>";
	echo "Registration code: <input type='text' name='regcode'><BR />";
	echo "<input type='hidden' name='option' value='com_wikidauth' />";
	echo "<input type='hidden' name='task' value='register_submit' />";
	//token
	echo JHTML::_( 'form.token' );
        echo "<button class='button' onclick='return submitbutton(\'send\');'>";
	echo "	" . JText::_('SEND');
        echo "</button>";
	echo "<BR /><BR /><BR /><BR />";
    }

    function register_submit()
    {

	$user =& JFactory::getUser(); 

	if ( $user->get('id') == 0 ) {
	    // You must be logged in!
	    return JError::raiseWarning('SOME_ERROR_CODE', JText::_('You must be logged in to use this function.'));
	}

	$username = $user->get('name');

	// Make sure we actually have a register code.
	$regcode = JRequest::getVar('regcode', null, 'post', 'cmd');

	// Acctually register the token by calling the register function in plugin.
	$plugin = JPluginHelper::getPlugin('authentication', 'wikidauth');
	JPluginHelper::importPlugin('authentication', 'wikidauth');

	$dispatcher = & JDispatcher::getInstance();

	$className = 'plg'.$plugin->type.$plugin->name;
	$wikidauth = new $className($dispatcher, (array)$plugin);

	$result = $wikidauth->register($username, $regcode);

	if ( $result == 0 ) {
	    echo "Token registered successfully.<br /><br />";
	} else {
	    echo "There was an error registering your token: $result<br /><br />";
	}
    }
}
