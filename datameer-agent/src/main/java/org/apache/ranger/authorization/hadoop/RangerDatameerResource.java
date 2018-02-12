package org.apache.ranger.authorization.hadoop;

import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;

public class RangerDatameerResource extends RangerAccessResourceImpl {

	public RangerDatameerResource(String path, String owner) {
		super.setValue(RangerDatameerAuthorizer.KEY_RESOURCE_PATH, path);
		super.setOwnerUser(owner);
	}
}