<?php
if (!defined('BASEPATH'))
    exit('No direct script access allowed');

class Auth extends CI_Model
{
    
    function __construct()
    {
        parent::__construct();
        
        $logged_in = $this->session->userdata('logged_in');
        
        if (!isset($logged_in))
            $this->session_defaults();
    }
    
    function session_defaults()
    {
        $session = array(
            'logged_in' => false,
            'uid' => 0,
            'username' => '',
            'name' => ''
        );
        $this->session->set_userdata($session);
    }
    
    function check_login($username, $password)
    {
        $password = sha1($password);
        
        $this->db->where('username', $username);
        $this->db->where('password', $password);
        
        $query = $this->db->get('users');
        
        $match = $query->row();
        
        if ($match) {
            $this->set_session($match);
            return true;
        } else {
            $this->failed = true;
            return false;
        }
    }
    
    function set_session($match, $init = true)
    {
        $id       = $match->id;
        $userdata = array(
            'uid' => $id,
            'username' => htmlspecialchars($match->username),
            'name' => htmlspecialchars($match->first_name . ' ' . $match->last_name),
            'logged_in' => true
        );
        
        $this->session->set_userdata($userdata);
        
        if ($init) {
            $session = $this->session->userdata('session_id');
            $ip      = $this->input->ip_address();
            $data    = array(
                'session' => $session,
                'ip' => $ip
            );
            $this->db->where('id', $id);
            $this->db->update('users', $data);
        }
    }
    
    function check_session()
    {
        $username = $this->session->userdata('username');
        $session  = $this->session->userdata('session_id');
        $ip       = $this->input->ip_address();
        $this->db->where('username', $username);
        $this->db->where('session', $session);
        $this->db->where('ip', $ip);
        $this->db->from('users');
        
        $result = $this->db->count_all_results();
        
        if ($result > 0) {
            return true;
        } else {
            $this->session_defaults();
            return false;
        }
    }
    
    function authenticate($username, $password)
    {
        $ret = $this->check_login($username, $password);
        if (!$ret) {
            $this->session->sess_destroy();
            $this->session_defaults();
        }
        return $ret;
    }
    
    function verify()
    {
        $session = $this->check_session();
        return $session;
    }
    
    function logout()
    {
        $this->session->sess_destroy();
        $this->session_defaults();
    }
}
