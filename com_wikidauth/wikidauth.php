<?php
// no direct access
defined('_JEXEC') or die('Restricted access');

jimport('joomla.application.component.helper');

require_once(JPATH_COMPONENT.DS.'controller.php');

// Create the controller
$controller = new WikidAuthController();

// Perform the Request task
$controller->execute(JRequest::getVar('task', null, 'default', 'cmd'));

// Redirect if set by the controller
$controller->redirect();
