package org.globaltester.cryptoprovider.bc;

import org.globaltester.cryptoprovider.Cryptoprovider;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public class Activator implements BundleActivator {

	private static BundleContext context;

	public static BundleContext getContext() {
		return context;
	}

	/*
	 * (non-Javadoc)
	 * @see org.osgi.framework.BundleActivator#start(org.osgi.framework.BundleContext)
	 */
	public void start(BundleContext bundleContext) throws Exception {
		// System.out.println("START Activator bc");
		Activator.context = bundleContext;

		String str = Cryptoprovider.class.getName();
		// System.out.println("Cryptoprovider bc: " +str);

		//register service in service registry
		Cryptoprovider cryptoProvider = ProviderBc.getInstance();
		bundleContext.registerService(Cryptoprovider.class, cryptoProvider, cryptoProvider.getProperties());
		// System.out.println("END Activator bc");
	}

	/*
	 * (non-Javadoc)
	 * @see org.osgi.framework.BundleActivator#stop(org.osgi.framework.BundleContext)
	 */
	public void stop(BundleContext bundleContext) throws Exception {
		Activator.context = null;
	}

}
