package org.apache.ranger.services.datameer.client.valuetypes;

import java.util.List;

import org.immutables.gson.Gson;
import org.immutables.value.Value.Immutable;

@Gson.TypeAdapters
@Immutable
public abstract class Value {

	public abstract List<FolterItem> folders();
}