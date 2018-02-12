package org.apache.ranger.services.datameer.client.valuetypes;

import org.immutables.gson.Gson;
import org.immutables.value.Value.Immutable;

@Gson.TypeAdapters
@Immutable
public abstract class Attribute {
	public abstract String path();
}