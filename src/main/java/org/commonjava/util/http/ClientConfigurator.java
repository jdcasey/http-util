package org.commonjava.util.http;

import org.apache.http.impl.client.AbstractHttpClient;

public interface ClientConfigurator
{

    void configure( AbstractHttpClient client )
        throws HTTPException;

}
