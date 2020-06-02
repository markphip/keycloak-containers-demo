<?php
$config = array(
    'admin' => array(
        'core:AdminPassword',
    ),
    'example-userpass' => array(
        'exampleauth:UserPass',
        'markphip:test123' => array(
            'groups' => array('admins'),
            'email' => 'markphip@gmail.com',
            'uid' => 'markphip',
        ),
        'mphippard:saml123' => array(
            'groups' => array('editors'),
            'email' => 'mphippard@digital.ai',
            'uid' => 'mphippard',
        ),
        'jmcnally:john123' => array(
            'groups' => array(),
            'email' => 'jmcnally@digital.ai',
            'uid' => 'jmcnally',
        ),
    ),
);