package org.apache.ranger.services.datameer.client.valuetypes;

import java.util.List;

import org.immutables.gson.Gson;
import org.immutables.value.Value.Immutable;

@Gson.TypeAdapters
@Immutable
public abstract class FolterItem {
	public abstract Attribute attr();

	public abstract String data();

	public abstract List<FolterItem> children();
}
