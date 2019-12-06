/**
 * @ Copyright IBM Corporation 2016.
 * @ Copyright HCL Technologies Ltd. 2017, 2019.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.jenkins.plugin.scanners;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.hcl.appscan.jenkins.plugin.Messages;
import com.hcl.appscan.jenkins.plugin.auth.ASoCCredentials;
import java.util.HashMap;
import java.util.Map;

import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.presence.CloudPresenceProvider;
import com.hcl.appscan.jenkins.plugin.auth.JenkinsAuthenticationProvider;
import com.hcl.appscan.sdk.app.CloudApplicationProvider;

import hudson.Extension;
import hudson.RelativePath;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import hudson.util.VariableResolver;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

public class MobileAnalyzer extends Scanner {

	private static final String MOBILE_ANALYZER = "ASoC Mobile Analyzer"; //$NON-NLS-1$
	
	private String m_credentials;
	private String m_application;
	private String m_loginUser;
	private Secret m_loginPassword;
	private String m_extraField;
	private String m_presenceId;
	private String m_testName;
	private boolean m_email;
	private boolean m_wait;
	private boolean m_failBuildNonCompliance;
	private boolean m_failBuild;
	
	@Deprecated
	public MobileAnalyzer(String target) {
		this(target, false);
	}
	
	@Deprecated
	public MobileAnalyzer(String target, boolean hasOptions, String credentials, String application, String loginUser, String loginPassword, String extraField, String presenceId, String testName, boolean email, boolean wait, boolean failBuildNonCompliance, boolean failBuild) {
		super(target, hasOptions);
		m_credentials = credentials;
		m_application = application;
		m_loginUser = loginUser;
		m_loginPassword = Secret.fromString(loginPassword);
		m_extraField = extraField;
		m_presenceId = presenceId;
		m_testName = (testName == null || testName.trim().equals("")) ? "" + ThreadLocalRandom.current().nextInt(0, 10000) : testName;
		m_email = email;
		m_wait = wait;
		m_failBuildNonCompliance = failBuildNonCompliance;
		m_failBuild = failBuild;
	}
	
	@DataBoundConstructor
	public MobileAnalyzer(String target, boolean hasOptions) {
		super(target, hasOptions);
		m_credentials = EMPTY;
		m_application = EMPTY;
		m_loginUser = EMPTY;
		m_loginPassword = Secret.fromString(EMPTY);
		m_extraField = EMPTY;
		m_presenceId = EMPTY;
		m_testName = EMPTY;
		m_email = false;
		m_wait = false;
		m_failBuildNonCompliance = false;
		m_failBuild = false;
	}
	
	@DataBoundSetter
	public void setCredentials(String credentials) {
		m_credentials = credentials;
	}
        
	public String getCredentials() {
		return m_credentials;
	}
	
	@DataBoundSetter
	public void setApplication(String application) {
		m_application = application;
	}
	
	public String getApplication() {
		return m_application;
	}
	
	@DataBoundSetter
	public void setLoginUser(String loginUser) {
		m_loginUser = loginUser;
	}
	
	public String getLoginUser() {
		return m_loginUser;
	}
	
	@DataBoundSetter
	public void setLoginPassword(String loginPassword) {
		m_loginPassword = Secret.fromString(loginPassword);
	}
	
	public Secret getLoginPassword() {
		return m_loginPassword;
	}
	
	@DataBoundSetter
	public void setExtraField(String extraField) {
		m_extraField = extraField;
	}
	
	public String getExtraField() {
		return m_extraField;
	}

	@DataBoundSetter
	public void setPresenceId(String presenceId) {
		m_presenceId = presenceId;
	}
	
	public String getPresenceId() {
		return m_presenceId;
	}
	
	@DataBoundSetter
	public void setTestName(String testName) {
		m_testName = testName;
	}
	
	public String getTestName() {
		return m_testName;
	}
	
	@DataBoundSetter
	public void setEmail(boolean email) {
		m_email = email;
	}
	
	public boolean getEmail() {
		return m_email;
	}
	
	@DataBoundSetter
	public void setWait(boolean wait) {
		m_wait = wait;
	}
	
	public boolean getWait() {
		return m_wait;
	}
	
	@DataBoundSetter
	public void setFailBuildNonCompliance(boolean failBuildNonCompliance){
		m_failBuildNonCompliance=failBuildNonCompliance;
	}

	public boolean getFailBuildNonCompliance(){
		return m_failBuildNonCompliance;
	}
	
	@DataBoundSetter
	public void setFailBuild(boolean failBuild) {
		m_failBuild = failBuild;
	}
	
	public boolean getFailBuild() {
		return m_failBuild;
	}
	
	@Override
	public String getType() {
		return MOBILE_ANALYZER;
	}
	
	@Override
	public Map<String, String> getProperties(VariableResolver<String> resolver) {
		Map<String, String> properties = new HashMap<String, String>();
		properties.put(TARGET, resolver == null ? getTarget() : resolvePath(getTarget(), resolver));
		properties.put("credentials", m_credentials);
		properties.put("applicationId", m_application);
		properties.put(LOGIN_USER, m_loginUser);
		properties.put(LOGIN_PASSWORD, Secret.toString(m_loginPassword));
		properties.put(EXTRA_FIELD, m_extraField);
		properties.put(PRESENCE_ID, m_presenceId);
		properties.put("testName", m_testName);
		properties.put("email", Boolean.toString(m_email));
		properties.put("wait", Boolean.toString(m_wait));
		properties.put("failBuildNonCompliance", Boolean.toString(m_failBuildNonCompliance));
		properties.put("failBuild", Boolean.toString(m_failBuild));
		return properties;
	}

	@Symbol("mobile_analyzer") //$NON-NLS-1$
	@Extension
	public static final class DescriptorImpl extends ScanDescriptor {
		
		@Override
		public String getDisplayName() {
			return MOBILE_ANALYZER;
		}
		
		public FormValidation doCheckTarget(@QueryParameter String target) {
	    		return FormValidation.validateRequired(target);
	    	}
		
		public ListBoxModel doFillCredentialsItems(@QueryParameter String credentials, @AncestorInPath ItemGroup<?> context) {
			//We could just use listCredentials() to get the ListBoxModel, but need to work around JENKINS-12802.
			ListBoxModel model = new ListBoxModel();
			List<ASoCCredentials> credentialsList = CredentialsProvider.lookupCredentials(ASoCCredentials.class, context,
					ACL.SYSTEM, Collections.<DomainRequirement>emptyList());
			boolean hasSelected = false;

			for(ASoCCredentials creds : credentialsList) {
				if(creds.getId().equals(credentials))
					hasSelected = true;
				String displayName = creds.getDescription();
				displayName = displayName == null || displayName.equals("") ? creds.getUsername() + "/******" : displayName; //$NON-NLS-1$
				model.add(new ListBoxModel.Option(displayName, creds.getId(), creds.getId().equals(credentials))); //$NON-NLS-1$
			}
			if(!hasSelected)
				model.add(new ListBoxModel.Option("", "", true)); //$NON-NLS-1$ //$NON-NLS-2$
			return model;
		}
                
		public FormValidation doCheckCredentials(@QueryParameter String credentials, @AncestorInPath ItemGroup<?> context) {
			if(credentials.trim().equals("")) //$NON-NLS-1$
				return FormValidation.errorWithMarkup(Messages.error_no_creds("/credentials")); //$NON-NLS-1$

			IAuthenticationProvider authProvider = new JenkinsAuthenticationProvider(credentials, context);
			if(authProvider.isTokenExpired())
				return FormValidation.errorWithMarkup(Messages.error_token_expired("/credentials")); //$NON-NLS-1$

			return FormValidation.ok();
		}
		
		public ListBoxModel doFillApplicationItems(@QueryParameter String credentials, @AncestorInPath ItemGroup<?> context) {
		    IAuthenticationProvider authProvider = new JenkinsAuthenticationProvider(credentials, context);
		    Map<String, String> applications = new CloudApplicationProvider(authProvider).getApplications();
		    ListBoxModel model = new ListBoxModel();

		    if(applications != null) {
			    List<Map.Entry<String , String>> list=sortApplications(applications.entrySet());

			    for(Map.Entry<String, String> entry : list)
				    model.add(entry.getValue(), entry.getKey());
		    }
		    return model;
		}
    	
		private List<Map.Entry<String , String>> sortApplications(Set<Map.Entry<String , String>> set) {
			List<Map.Entry<String , String>> list= new ArrayList<>(set);
			if (list.size()>1) {
				Collections.sort( list, new Comparator<Map.Entry<String, String>>()
			{
			    public int compare( Map.Entry<String, String> o1, Map.Entry<String, String> o2 )
			    {
				return (o1.getValue().toLowerCase()).compareTo( o2.getValue().toLowerCase() );
			    }
			} );
			}
			return list;
		}
		
	    	public ListBoxModel doFillPresenceIdItems(@RelativePath("..") @QueryParameter String credentials, @AncestorInPath ItemGroup<?> context) { //$NON-NLS-1$
	    		IAuthenticationProvider authProvider = new JenkinsAuthenticationProvider(credentials, context);
	    		Map<String, String> presences = new CloudPresenceProvider(authProvider).getPresences();
	    		ListBoxModel model = new ListBoxModel();
	    		model.add(""); //$NON-NLS-1$
	
    			if(presences != null) {
		    		for(Map.Entry<String, String> entry : presences.entrySet())
		    			model.add(entry.getValue(), entry.getKey());
	    		}
	    		return model;
		}
	}
}