package org.commonjava.util.http.ssl.impl;

import static org.commonjava.util.http.util.SSLUtils.loadDefaultKeystore;
import static org.commonjava.util.http.util.SSLUtils.readCerts;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import javax.enterprise.inject.Alternative;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.commonjava.util.http.HTTPException;
import org.commonjava.util.http.ssl.SSLResourceLoader;
import org.commonjava.util.http.ssl.conf.KeyConfig;
import org.commonjava.util.http.ssl.conf.TrustConfig;

@Alternative
public class PathSSLResourceLoader
    implements SSLResourceLoader
{
    private static final String CLASSPATH_PREFIX = "classpath:";

    //    private static final String CLIENT_SUBPATH = "client";

    private static final String SERVER_SUBPATH = "server";

    private final String path;

    public PathSSLResourceLoader( final String path )
    {
        this.path = path;
    }

    @Override
    public KeyConfig getKeyConfig()
        throws HTTPException
    {
        // TODO: Load key PEM files somehow...not sure about passwords for keys, though.
        //        final String basedir = new File( path, CLIENT_SUBPATH ).getPath();
        final KeyStore ks = loadDefaultKeystore();

        KeyManagerFactory kmf;
        try
        {
            kmf = KeyManagerFactory.getInstance( KeyManagerFactory.getDefaultAlgorithm() );
            kmf.init( ks, null );
        }
        catch ( final NoSuchAlgorithmException e )
        {
            throw new HTTPException( "Cannot initialize KeyManagerFactory: %s", e, e.getMessage() );
        }
        catch ( final UnrecoverableKeyException e )
        {
            throw new HTTPException( "Cannot initialize KeyManagerFactory: %s", e, e.getMessage() );
        }
        catch ( final KeyStoreException e )
        {
            throw new HTTPException( "Cannot initialize KeyManagerFactory: %s", e, e.getMessage() );
        }

        X509KeyManager km = null;
        for ( final KeyManager keyManager : kmf.getKeyManagers() )
        {
            if ( keyManager instanceof X509KeyManager )
            {
                km = (X509KeyManager) keyManager;
            }
        }

        return new KeyConfig( ks, new MultiKeyManager( km ) );
    }

    @Override
    public TrustConfig getTrustConfig()
        throws HTTPException
    {
        final String basedir = new File( path, SERVER_SUBPATH ).getPath();

        final KeyStore ks = loadDefaultKeystore();

        if ( basedir.startsWith( CLASSPATH_PREFIX ) )
        {
            final String cpDir = basedir.substring( CLASSPATH_PREFIX.length() );
            loadFromClasspath( cpDir, ks );
        }
        else
        {
            final File dir = new File( basedir );
            if ( dir.exists() && dir.isDirectory() )
            {
                final String[] fnames = dir.list();
                if ( fnames != null )
                {
                    for ( final String fname : fnames )
                    {
                        final File f = new File( dir, fname );
                        loadFromFile( f.getPath(), ks );
                    }
                }
            }
        }

        TrustManagerFactory dtmf;
        try
        {
            dtmf = TrustManagerFactory.getInstance( TrustManagerFactory.getDefaultAlgorithm() );
            dtmf.init( (KeyStore) null );
        }
        catch ( final NoSuchAlgorithmException e )
        {
            throw new HTTPException( "Failed to initialize default trust-store: %s", e, e.getMessage() );
        }
        catch ( final KeyStoreException e )
        {
            throw new HTTPException( "Failed to initialize default trust-store: %s", e, e.getMessage() );
        }

        X509TrustManager dtm = null;
        for ( final TrustManager ctm : dtmf.getTrustManagers() )
        {
            if ( ctm instanceof X509TrustManager )
            {
                dtm = (X509TrustManager) ctm;
                break;
            }
        }

        try
        {
            if ( ks.size() < 1 )
            {
                return new TrustConfig( ks, new MultiTrustManager( dtm ) );
            }
        }
        catch ( final KeyStoreException e )
        {
        }

        TrustManagerFactory tmf;
        try
        {
            tmf = TrustManagerFactory.getInstance( TrustManagerFactory.getDefaultAlgorithm() );
            tmf.init( ks );
        }
        catch ( final NoSuchAlgorithmException e )
        {
            throw new HTTPException( "Failed to initialize trust-store from .pem files: %s", e, e.getMessage() );
        }
        catch ( final KeyStoreException e )
        {
            throw new HTTPException( "Failed to initialize trust-store from .pem files: %s", e, e.getMessage() );
        }

        X509TrustManager tm = null;
        for ( final TrustManager ctm : tmf.getTrustManagers() )
        {
            if ( ctm instanceof X509TrustManager )
            {
                tm = (X509TrustManager) ctm;
                break;
            }
        }

        return new TrustConfig( ks, new MultiTrustManager( tm, dtm ) );
    }

    private static void loadFromClasspath( final String basepath, final KeyStore ks )
        throws HTTPException
    {
        Enumeration<URL> resources;
        try
        {
            resources = Thread.currentThread()
                              .getContextClassLoader()
                              .getResources( basepath );
        }
        catch ( final IOException e )
        {
            throw new HTTPException( "Failed to scan classpath for certificate base path: %s. Reason: %s", e, basepath,
                                     e.getMessage() );
        }

        final List<URL> urls = Collections.list( resources );
        for ( final URL url : urls )
        {
            if ( "jar".equals( url.getProtocol() ) )
            {
                loadFromJar( url, basepath, ks );
            }
            else
            {
                loadFromFile( url.getPath(), ks );
            }
        }
    }

    private static void loadFromFile( final String path, final KeyStore ks )
        throws HTTPException
    {
        final File f = new File( path );
        if ( f.exists() && f.isFile() )
        {
            InputStream is = null;
            try
            {
                is = new FileInputStream( f );
                readCerts( is, f.getName(), ks );
            }
            catch ( final CertificateException e )
            {
                throw new HTTPException( "Failed to read classpath certificate file: %s. Reason: %s", e, f,
                                         e.getMessage() );
            }
            catch ( final KeyStoreException e )
            {
                throw new HTTPException( "Failed to add certificate from classpath file: %s. Reason: %s", e, f,
                                         e.getMessage() );
            }
            catch ( final NoSuchAlgorithmException e )
            {
                throw new HTTPException( "Failed to read classpath certificate file: %s. Reason: %s", e, f,
                                         e.getMessage() );
            }
            catch ( final IOException e )
            {
                throw new HTTPException( "Failed to read classpath certificate file: %s. Reason: %s", e, f,
                                         e.getMessage() );
            }
            finally
            {
                if ( is != null )
                {
                    try
                    {
                        is.close();
                    }
                    catch ( final IOException e )
                    {
                    }
                }
            }
        }
    }

    private static void loadFromJar( final URL url, final String basepath, final KeyStore ks )
        throws HTTPException
    {
        String jar = url.getPath();
        final int idx = jar.indexOf( "!" );
        if ( idx > -1 )
        {
            jar = jar.substring( 0, idx );
        }

        if ( jar.startsWith( "file:" ) )
        {
            jar = jar.substring( 5 );
        }

        try
        {
            final JarFile jf = new JarFile( jar );

            final List<JarEntry> entries = Collections.list( jf.entries() );
            for ( final JarEntry entry : entries )
            {
                final String name = entry.getName();
                if ( name.startsWith( basepath ) )
                {
                    final InputStream is = jf.getInputStream( entry );
                    try
                    {
                        readCerts( is, new File( name ).getName(), ks );
                    }
                    catch ( final CertificateException e )
                    {
                        throw new HTTPException(
                                                 "Failed to read certificates from classpath jar entry: %s!%s. Reason: %s",
                                                 e, jar, name, e.getMessage() );
                    }
                    catch ( final KeyStoreException e )
                    {
                        throw new HTTPException(
                                                 "Failed to read certificates from classpath jar entry: %s!%s. Reason: %s",
                                                 e, jar, name, e.getMessage() );
                    }
                    catch ( final NoSuchAlgorithmException e )
                    {
                        throw new HTTPException(
                                                 "Failed to read certificates from classpath jar entry: %s!%s. Reason: %s",
                                                 e, jar, name, e.getMessage() );
                    }
                    finally
                    {
                        if ( is != null )
                        {
                            try
                            {
                                is.close();
                            }
                            catch ( final IOException eInner )
                            {
                            }
                        }
                    }
                }
            }
        }
        catch ( final IOException e )
        {
            throw new HTTPException( "Failed to open classpath jar: %s. Reason: %s", e, jar, e.getMessage() );
        }
    }

}
