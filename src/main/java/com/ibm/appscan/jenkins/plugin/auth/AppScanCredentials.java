/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ibm.appscan.jenkins.plugin.auth;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.util.Secret;

/**
 *
 * @author anurag-s
 */
public abstract class AppScanCredentials extends UsernamePasswordCredentialsImpl{

    public AppScanCredentials(CredentialsScope scope, String id, String description, String username, String password) {
        super(scope, id, description, username, password);
    }
    public abstract String getServer();
    public abstract Secret getToken();
    public abstract void setToken(String connection);    
}
