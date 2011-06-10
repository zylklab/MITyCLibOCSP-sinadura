/**
 * LICENCIA LGPL:
 * 
 * Esta librería es Software Libre; Usted puede redistribuirlo y/o modificarlo
 * bajo los términos de la GNU Lesser General Public License (LGPL)
 * tal y como ha sido publicada por la Free Software Foundation; o
 * bien la versión 2.1 de la Licencia, o (a su elección) cualquier versión posterior.
 * 
 * Esta librería se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
 * GARANTÍA; tampoco las implícitas garantías de MERCANTILIDAD o ADECUACIÓN A UN
 * PROPÓSITO PARTICULAR. Consulte la GNU Lesser General Public License (LGPL) para más
 * detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL)
 * junto con esta librería; si no es así, escriba a la Free Software Foundation Inc.
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA.
 *
 */
package es.mityc.javasign.certificate.ocsp.examples;

import es.mityc.javasign.trust.PropsTruster;
import es.mityc.javasign.trust.TrustAdapter;

/**
 * <p>Gestiona las entidades de confianza que admite MITyC.</p>
 * <p>Esta clase se basa en ficheros de configuración para parametrizar los certificados admitidos (en /trust/mitycsimple.properties).</p>
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class MyPropsTruster extends PropsTruster {

	/** Fichero de configuración. */
	private static final String CONF_FILE = "trust/mytruster.properties";

	/**
	 * <p>Constructor.</p>
	 * @param fileconf
	 */
	private MyPropsTruster() {
		super(CONF_FILE);
	}

	/**
	 * <p>Devuelve una instancia única del gestionador de confianza del MITyC.</p>
	 * @return Instancia de este gestionador de confianza
	 */
	public static TrustAdapter getInstance() {
		if (instance == null) {
			instance = new MyPropsTruster();
		}
		return instance;
	}
}
