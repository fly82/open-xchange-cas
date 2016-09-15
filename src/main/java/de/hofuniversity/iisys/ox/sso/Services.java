package de.hofuniversity.iisys.ox.sso;

import java.util.concurrent.atomic.AtomicReference;

import com.openexchange.server.ServiceLookup;

/**
 * CAS authentication handler lookup.
 */
public class Services
{
    /**
     * Initializes a new {@link Services}.
     */
    private Services() {
        super();
    }

    private static final AtomicReference<ServiceLookup> REF =
        new AtomicReference<ServiceLookup>();

    /**
     * Sets the service lookup.
     *
     * @param serviceLookup The service lookup or <code>null</code>
     */
    public static void setServiceLookup(final ServiceLookup serviceLookup)
    {
        REF.set(serviceLookup);
    }

    /**
     * Gets the service lookup.
     *
     * @return The service lookup or <code>null</code>
     */
    public static ServiceLookup getServiceLookup() {
        return REF.get();
    }

    /**
     * Gets the service of specified type
     *
     * @param clazz The service's class
     * @return The service
     * @throws IllegalStateException If an error occurs while returning the
     *      demanded service
     */
    public static <S extends Object> S getService(
        final Class<? extends S> clazz)
    {
        final com.openexchange.server.ServiceLookup serviceLookup = REF.get();
        if (null == serviceLookup)
        {
            throw new IllegalStateException("Missing ServiceLookup " +
                "instance. Bundle \"de.hofuniversity.iisys.ox." +
                "sso\" not started?");
        }
        return serviceLookup.getService(clazz);
    }

    /**
     * (Optionally) Gets the service of specified type
     *
     * @param clazz The service's class
     * @return The service or <code>null</code> if absent
     */
    public static <S extends Object> S optService(final Class<? extends S> clazz)
    {
        try
        {
            return getService(clazz);
        }
        catch (final IllegalStateException e)
        {
            return null;
        }
    }
}
