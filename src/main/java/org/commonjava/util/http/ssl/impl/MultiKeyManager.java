package org.commonjava.util.http.ssl.impl;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.X509KeyManager;

public class MultiKeyManager
    implements X509KeyManager
{

    private final List<X509KeyManager> delegates;

    public MultiKeyManager( final X509KeyManager... delegates )
    {
        this.delegates = new ArrayList<X509KeyManager>( Arrays.asList( delegates ) );
    }

    @Override
    public String chooseClientAlias( final String[] keyTypes, final Principal[] issuers, final Socket socket )
    {
        for ( final X509KeyManager mgr : delegates )
        {
            final String alias = mgr.chooseClientAlias( keyTypes, issuers, socket );
            if ( alias != null )
            {
                return alias;
            }
        }

        return null;
    }

    @Override
    public String chooseServerAlias( final String keyType, final Principal[] issuers, final Socket socket )
    {
        for ( final X509KeyManager mgr : delegates )
        {
            final String alias = mgr.chooseServerAlias( keyType, issuers, socket );
            if ( alias != null )
            {
                return alias;
            }
        }

        return null;
    }

    @Override
    public X509Certificate[] getCertificateChain( final String alias )
    {
        for ( final X509KeyManager mgr : delegates )
        {
            final X509Certificate[] chain = mgr.getCertificateChain( alias );
            if ( chain != null )
            {
                return chain;
            }
        }

        return null;
    }

    @Override
    public String[] getClientAliases( final String keyType, final Principal[] issuers )
    {
        final Set<String> aliases = new LinkedHashSet<String>();
        for ( final X509KeyManager mgr : delegates )
        {
            final String[] a = mgr.getClientAliases( keyType, issuers );
            if ( a != null )
            {
                aliases.addAll( Arrays.asList( a ) );
            }
        }

        return aliases.isEmpty() ? null : aliases.toArray( new String[] {} );
    }

    @Override
    public PrivateKey getPrivateKey( final String alias )
    {
        for ( final X509KeyManager mgr : delegates )
        {
            final PrivateKey pk = mgr.getPrivateKey( alias );
            if ( pk != null )
            {
                return pk;
            }
        }

        return null;
    }

    @Override
    public String[] getServerAliases( final String keyType, final Principal[] issuers )
    {
        final Set<String> aliases = new LinkedHashSet<String>();
        for ( final X509KeyManager mgr : delegates )
        {
            final String[] a = mgr.getServerAliases( keyType, issuers );
            if ( a != null )
            {
                aliases.addAll( Arrays.asList( a ) );
            }
        }

        return aliases.isEmpty() ? null : aliases.toArray( new String[] {} );
    }

}
