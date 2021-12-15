<?php

/**
 * OpenLDAP + Kerberos authentication backend
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Sebastián Santisi <s@ntisi.com.ar>
 */
class auth_plugin_authopenldapkerberos extends DokuWiki_Auth_Plugin
{
    /** @var array filter pattern */
    protected $pattern = array();

    public function __construct()
    {
        parent::__construct();

        if(!function_exists('ldap_connect') || !class_exists('KRB5CCache')) {
            // This condition isn't checking for a valid Kerberos ticket or for
            // a system GSSAPI library, the only way to check that is trying to
            // bind to LDAP.
            $this->success = false;
            return;
        }

        $this->cando['getUsers']     = true;
        $this->cando['getUserCount'] = true;
        $this->cando['getGroups']    = true;
    }

    public function checkPass($user, $pass)
    {
        try {
            $p = new KRB5CCache();
            $p->initPassword($user, $pass);
            return true;
        }
        catch(Exception $e) {
            return false;
        }
    }

    public function getUserData($user, $requireGroups = true)
    {
        $c = $this->connect();
        $r = ldap_search(
            $c,
            "ou={$this->getConf('user_ou')},{$this->getConf('base_dn')}",
            "({$this->getConf('userkey')}=$user)",
            Array($this->getConf('username'), $this->getConf('usergid'), $this->getConf('usermail'))
        );

        $e = ldap_get_entries($c, $r);

        $userdata = Array(
            'name' => $e[0][$this->getConf('username')][0],
            'mail' => $e[0][$this->getConf('usermail')][0],
            'grps' => Array()
	    );

        if($requireGroups) {
            $gid = $e[0][$this->getConf('usergid')][0];

            $r = ldap_search(
                $c,
                "ou={$this->getConf('group_ou')},{$this->getConf('base_dn')}",
                "({$this->getConf('groupkey')}=*)",
                Array($this->getConf('groupkey'), $this->getConf('groupgid'), $this->getConf('groupuids'))
            );
            $e = ldap_get_entries($c, $r);

            for($i = 0; $i < $e['count']; $i++) {
                $cn = $e[$i][$this->getConf('groupkey')][0];
                $gn = $e[$i][$this->getConf('groupgid')]['0'];

                if($gn == $gid)
                    $userdata['grps'][] = $cn;
                else if(array_key_exists($this->getConf('groupuids'), $e[$i])) {
                    for($j = 0; $j < $e[$i][$this->getConf('groupuids')]['count']; $j++) {
                        if($e[$i][$this->getConf('groupuids')][$j] == $user)
                             $userdata['grps'][] = $cn;
                    }
                }
            }
        }

        ldap_unbind($c);

        return $userdata;
    }

    protected function connect() {
        $c = ldap_connect($this->getConf('server'), $this->getConf('port'));
        ldap_set_option($c, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_sasl_bind($c, NULL, NULL, 'GSSAPI');
        return $c;
    }

    public function getUserCount($filter = array())
    {
        $c = $this->connect();
        $r = ldap_search(
            $c,
            "ou={$this->getConf('user_ou')},{$this->getConf('base_dn')}",
            "({$this->getConf('userkey')}=*)",
            Array($this->getConf('usergid'))
        );
        $e = ldap_get_entries($c, $r);

        ldap_unbind($c);

        return $e['count'];
    }

    public function retrieveUsers($start = 0, $limit = 0, $filter = array())
    {
        $this->constructPattern($filter);

        $c = $this->connect();
        $r = ldap_search(
            $c,
            "ou={$this->getConf('user_ou')},{$this->getConf('base_dn')}",
            "({$this->getConf('userkey')}=*)",
            Array($this->getConf('userkey'), $this->getConf('username'), $this->getConf('usergid'), $this->getConf('usermail'))
        );
        $e = ldap_get_entries($c, $r);

        $users = Array();

        for($i = 0; $i < $e['count']; $i++)
            $users[$e[$i][$this->getConf('userkey')][0]] = Array(
                'name' => $e[$i][$this->getConf('username')][0],
                'mail' => $e[$i][$this->getConf('usermail')][0],
                'grps' => Array(),
                'gid' => $e[$i][$this->getConf('usergid')][0]
            );

        $r = ldap_search(
            $c,
            "ou={$this->getConf('group_ou')},{$this->getConf('base_dn')}",
            "({$this->getConf('groupkey')}=*)",
            Array($this->getConf('groupkey'), $this->getConf('groupgid'), $this->getConf('groupuids'))
        );
	    $e = ldap_get_entries($c, $r);

        ldap_unbind($c);

        $groups = Array();

        for($i = 0; $i < $e['count']; $i++) {
            $cn = $e[$i][$this->getConf('groupkey')][0];
            $gn = $e[$i][$this->getConf('groupgid')]['0'];

            $groups[$gn] = $cn;

            if(array_key_exists($this->getConf('groupuids'), $e[$i]))
                for($j = 0; $j < $e[$i][$this->getConf('groupuids')]['count']; $j++)
                    $users[$e[$i][$this->getConf('groupuids')][$j]]['grps'][] = $cn;
        }

        $out = Array();

        $uids = array_keys($users);
        sort($uids);

        foreach($uids as $uid) {
            $users[$uid]['grps'][] = $groups[$users[$uid]['gid']];

            if($this->filter($uid, $users[$uid])) {
                if($start > 0)
                    $start--;
                else {
                    $out[$uid] = $users[$uid];
                    if(count($out) == $limit)
                        break;
                }
            }
        }

        return $out;
    }

    public function retrieveGroups($start = 0, $limit = 0)
    {
        $c = $this->connect();
        $r = ldap_search(
            $c,
            "ou={$this->getConf('group_ou')},{$this->getConf('base_dn')}",
            "({$this->getConf('groupkey')}=*)",
            Array($this->getConf('groupkey'))
        );
        $e = ldap_get_entries($c, $r);

        ldap_unbind($c);

        if($limit == 0 || $limit > $e['count']) $limit = $e['count'];

        $groups = Array();

        for($i = $start; $i < $limit; $i++) {
                $groups[] = $e[$i][$this->getConf('groupkey')][0];
        }

        return $groups;
    }


    /**
     * return true if $user + $info match $filter criteria, false otherwise
     *
     * @author   Chris Smith <chris@jalakai.co.uk>
     *
     * @param string $user User login
     * @param array  $info User's userinfo array
     * @return bool
     */
    protected function filter($user, $info)
    {
        foreach ($this->pattern as $item => $pattern) {
            if ($item == 'user') {
                if (!preg_match($pattern, $user)) return false;
            } elseif ($item == 'grps') {
                if (!count(preg_grep($pattern, $info['grps']))) return false;
            } else {
                if (!preg_match($pattern, $info[$item])) return false;
            }
        }
        return true;
    }

    /**
     * construct a filter pattern
     *
     * @param array $filter
     */
    protected function constructPattern($filter)
    {
        $this->pattern = array();
        foreach ($filter as $item => $pattern) {
            $this->pattern[$item] = '/'.str_replace('/', '\/', $pattern).'/i'; // allow regex characters
        }
    }
}
