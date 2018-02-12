package org.apache.ranger.services.datameer.client;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.util.ArrayList;

import org.apache.commons.io.IOUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.Path;
import org.apache.ranger.services.datameer.client.valuetypes.FolderResult;
import org.apache.ranger.services.datameer.client.valuetypes.FolterItem;
import org.apache.ranger.services.datameer.client.valuetypes.GsonAdaptersAttribute;
import org.apache.ranger.services.datameer.client.valuetypes.GsonAdaptersFolderResult;
import org.apache.ranger.services.datameer.client.valuetypes.GsonAdaptersFolterItem;
import org.apache.ranger.services.datameer.client.valuetypes.GsonAdaptersValue;

import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class DatameerFileSystem {

	private static final String LIST_FOLDERS_URL = "/browser/listFolders";

	private static final Gson GSON = new GsonBuilder().registerTypeAdapterFactory(new GsonAdaptersAttribute())
			.registerTypeAdapterFactory(new GsonAdaptersFolderResult())
			.registerTypeAdapterFactory(new GsonAdaptersValue())
			.registerTypeAdapterFactory(new GsonAdaptersFolterItem()).create();

	private final Configuration _configuration;
	private final Folder _rootFolder = Folder.rootFolder();

	private DatameerFileSystem(Configuration configuration) throws IOException, URISyntaxException {
		_configuration = configuration;
		FolderResult folderResult = getListFolders(configuration);
		for (FolterItem item : folderResult.value().folders()) {
			_rootFolder.children().add(getFolder(_rootFolder, item));
		}
	}

	Folder getFolder(Folder parent, FolterItem actualFolder) {
		Folder folder = new Folder(actualFolder.data(), parent);
		for (FolterItem child : actualFolder.children()) {
			folder.children().add(getFolder(folder, child));
		}
		return folder;

	}

	public static DatameerFileSystem get(Configuration configuration)
			throws UnknownHostException, IOException, URISyntaxException {
		return new DatameerFileSystem(configuration);
	}

	private static HttpURLConnection toConnection(Configuration configuration, String suffix)
			throws IOException, URISyntaxException {
		URL resolvedUrl = new URI(configuration.get("datameer.url")).resolve(suffix).toURL();
		URLConnection connection = resolvedUrl.openConnection();
		String userPassword = configuration.get("datameer.username") + ":" + configuration.get("datameer.password");
		String encoding = BaseEncoding.base64().encode(userPassword.getBytes());
		connection.setRequestProperty("Authorization", "Basic " + encoding);
		connection.addRequestProperty("Accept", "application/json");
		connection.addRequestProperty("Content-Type", "application/json");
		return (HttpURLConnection) connection;

	}

	private static FolderResult getListFolders(Configuration configuration) throws IOException, URISyntaxException {
		HttpURLConnection connection = toConnection(configuration, LIST_FOLDERS_URL);
		connection.setRequestMethod("GET");
		connection.connect();
		InputStream inputStream = connection.getInputStream();
		String resultString = IOUtils.toString(inputStream);
		return GSON.fromJson(resultString, FolderResult.class);
	}

	public FileStatus[] listStatus(Path basePath) throws FileNotFoundException, IOException {
		Folder folder = new GetFolder(_rootFolder).existsRecursive(basePath);
		if (folder == null) {
			throw new FileNotFoundException(
					String.format("File or Folder with Path '%s' not found.", basePath.toString()));
		}
		ArrayList<Object> fileStatus = Lists.newArrayList();
		for (Folder child : folder.children()) {
			fileStatus.add(new FileStatus(0, true, 0, 0, 0, new Path(basePath, child.name())));
		}
		return fileStatus.toArray(new FileStatus[fileStatus.size()]);
	}

	public boolean exists(Path basePath) throws IOException {
		if (basePath.isRoot()) {
			return true;
		}
		if (basePath.isAbsolute()) {
			return new SearchFolder(_rootFolder).existsRecursive(basePath);
		}
		return false;
	}

	private static class SearchFolder {
		private Folder currentFolder;

		SearchFolder(Folder startFolder) {
			currentFolder = startFolder;
		}

		boolean existsRecursive(Path pathToSearch) {
			if (pathToSearch.isRoot()) {
				return true;
			}
			boolean exists = false;
			for (Folder child : currentFolder.children()) {
				if (pathToSearch.getName().equals(child.name())) {
					exists = true;
				}
			}
			return existsRecursive(pathToSearch.getParent()) && exists;
		}
	}

	private static class GetFolder {
		private Folder currentFolder;

		GetFolder(Folder startFolder) {
			currentFolder = startFolder;
		}

		Folder existsRecursive(Path pathToSearch) {
			if (pathToSearch.isRoot()) {
				return currentFolder;
			}
			Folder actualFolder = existsRecursive(pathToSearch.getParent());
			if (actualFolder == null) {
				return null;
			}
			boolean found = false;
			for (Folder child : actualFolder.children()) {
				if (pathToSearch.getName().equals(child.name())) {
					found = true;
					currentFolder = child;
				}
			}
			if (found) {
				return currentFolder;
			}
			return null;
		}
	}

}
