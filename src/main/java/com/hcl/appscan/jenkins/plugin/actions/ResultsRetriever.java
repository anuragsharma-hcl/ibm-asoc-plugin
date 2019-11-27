/**
 * © Copyright IBM Corporation 2016.
 * @ Copyright HCL Technologies Ltd. 2019.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.jenkins.plugin.actions;

import hudson.model.Action;
import hudson.model.Run;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;

import jenkins.model.RunAction2;
import jenkins.tasks.SimpleBuildStep;

import org.kohsuke.stapler.DataBoundConstructor;

import com.hcl.appscan.sdk.results.IResultsProvider;
import com.hcl.appscan.jenkins.plugin.Messages;

public class ResultsRetriever extends AppScanAction implements RunAction2, SimpleBuildStep.LastBuildAction {

	private final Run<?,?> m_build;	
	private IResultsProvider m_provider;
	private String m_name;

	@DataBoundConstructor
	public ResultsRetriever(Run<?,?> build, IResultsProvider provider, String scanName) {
		super(build.getParent());
		m_build = build;
		m_provider = provider;
		m_name = scanName;
	}

	@Override
	public String getDisplayName() {
		return Messages.label_running(m_name);
	}

	@Override
	public String getUrlName() {
		return null;
	}

	@Override
	public void onAttached(Run<?, ?> r) {
	}

	@Override
	public void onLoad(Run<?, ?> r) {
		checkResults(r);
	}
	
	@Override
	public Collection<? extends Action> getProjectActions() {
		HashSet<Action> actions = new HashSet<Action>();
		actions.add(new ScanResultsTrend(m_build, m_provider.getType(), m_name));
		return actions;
	}
	
	public boolean getHasResults() {
		return checkResults(m_build);
	}
	
	public boolean checkResults(Run<?,?> r) {
		if(r.getAllActions().contains(this) && m_provider.hasResults()) {
			r.getActions().remove(this); //We need to remove this action from the build, but getAllActions() returns a read-only list.
			r.addAction(createResults());
			try {
				r.save();
			} catch (IOException e) {
			}
			return true;
		}
		return false;
	}
	
	private ScanResults createResults() {
		return new ScanResults(
				m_build,
				m_provider,
				m_name,
				m_provider.getStatus(),
				m_provider.getFindingsCount(),
				m_provider.getHighCount(),
				m_provider.getMediumCount(),
				m_provider.getLowCount(),
				m_provider.getInfoCount());
	}
}
