package org.commonjava.util.http.ssl.path;

import static org.commonjava.util.http.ssl.SSLUtils.getDefaultKeyManager;
import static org.commonjava.util.http.ssl.SSLUtils.getDefaultTrustManager;
import static org.commonjava.util.http.ssl.SSLUtils.loadDefaultKeystore;
import static org.commonjava.util.http.ssl.SSLUtils.readCerts;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import javax.enterprise.context.ApplicationScoped;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.auth.AuthScope;
import org.commonjava.util.http.HTTPException;

@ApplicationScoped
public class PathSSLResourceLoader
{
    private static final String CLASSPATH_PREFIX = "classpath:";

    //    private static final String CLIENT_SUBPATH = "client";

    private static final String SERVER_SUBPATH = "server";

    private final String path;

    public PathSSLResourceLoader( final String path )
    {
        this.path = path;
    }

    public KeyConfig getKeyConfig()
        throws HTTPException
    {
        // TODO: Load key PEM files somehow...not sure about passwords for keys, though.
        //        final String basedir = new File( path, CLIENT_SUBPATH ).getPath();
        final KeyStore ks = loadDefaultKeystore();
        final X509KeyManager km = getDefaultKeyManager();

        return new KeyConfig( ks, new MultiKeyManager( km ) );
    }

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

        final X509TrustManager dtm = getDefaultTrustManager();

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
            final AuthScope scope = getAuthScope( f.getName() );
            try
            {
                is = new FileInputStream( f );
                readCerts( scope, is, ks );
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
                if ( entry.isDirectory() )
                {
                    continue;
                }

                final String name = entry.getName();
                if ( name.startsWith( basepath ) )
                {
                    final InputStream is = jf.getInputStream( entry );
                    final AuthScope scope = getAuthScope( name );

                    try
                    {
                        readCerts( scope, is, ks );
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

    private static AuthScope getAuthScope( final String name )
    {
        final String fname = new File( name ).getName();
        AuthScope scope = null;
        if ( fname.indexOf( '_' ) > -1 )
        {
            final String[] parts = fname.split( "_" );
            if ( parts.length > 1 && parts[1].matches( "\\d+" ) )
            {
                scope = new AuthScope( parts[0], Integer.parseInt( parts[1] ) );
            }
        }

        if ( scope == null )
        {
            scope = new AuthScope( fname, 443 );
        }

        return scope;
    }

}
