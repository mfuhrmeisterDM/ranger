package org.apache.ranger.services.datameer.client;

import java.util.List;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;

class Folder {
	private String name;
	private Folder parent;
	private List<Folder> children = Lists.newArrayList();

	private Folder() {
	}

	public Folder(String name, Folder parent) {
		this.parent = Preconditions.checkNotNull(parent);
		this.name = Preconditions.checkNotNull(name);
		Preconditions.checkArgument(this.name.contains("/"));
	}

	public static Folder rootFolder() {
		return new RootFolder();
	}

	public String name() {
		return name;
	}

	public Folder parent() {
		return parent;
	}

	List<Folder> children() {
		return children;
	}

	public String path() {
		return parent.path() + "/" + name;
	}

	private static class RootFolder extends Folder {

		private RootFolder() {
		}

		@Override
		public String name() {
			return "/";
		}

		@Override
		public Folder parent() {
			return null;
		}

		@Override
		public String path() {
			return "";
		}
	}
}