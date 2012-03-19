<?php
/*
 * modulo de seguridad para filtrado de xss e Injección SQL
 */
 
 abstract class patrones{
 	public $VULN = FALSE;
	protected $pat = array("--","\*","0x","\(","\)",">","<","\'","\"");
	//protected $pat = array("\W");
 }
 
 class VarTest extends patrones{
 	protected $audit= FALSE;
 	
 	function __construct(){
 		if(isset($_GET) || isset($_POST)):
 			$this->audit = TRUE;
 		endif;
 	}
 }
 
 
class Auditor extends VarTest{
 	/*
 	 * Test version 3.0
 	 */ 	
	function test(){
		if ($this->audit) {
			foreach(array($_GET,$_POST) as $method):
				foreach($method as $kget=>$vget):
					if(isset($method[$kget])):
					 	$tq = $method[$kget];
					 	foreach($this->pat as $patron):
					 		if(preg_match($patron,$tq)):
					 			$this->VULN = TRUE;
					 			return $this->VULN;
					 		else:
					 			$this->VULN = FALSE;
					 		endif;
					 	endforeach;
					endif;
				endforeach;
			endforeach;
		}
		return $this->VULN;
 	} 		
 	
 	/*
 	 * Mensaje passivo (sustituye) o
 	 * mensaje activo (muestra cartel con warning)
 	 */
 	 function chance($type="active"){
 		switch($type):
 			case "active":
	 			echo "<div id='error' style='position:absolute; top:200px;left:50%;background-color:#111;color:#C60F00;width:300px;height:300px;'>";
				echo "<h3>WARNING: </h3>";
				echo "Hacker está usted siendo investigado<hr>";
				echo "su Ip es: ".$_SERVER['REMOTE_ADDR']."<hr>";
				echo "Metodo: ".$_SERVER['REQUEST_METHOD']."<hr>";
				echo "Injection: ".$_SERVER['QUERY_STRING']."<hr>";
				echo "De donde viene IP: ".$_SERVER['REMOTE_ADDR']."<hr>";
				echo "</div>";
				break;
			default:
				$sus = '\\';
				/*
				 * Reemplaza en el método GET
				 * las variables vulnerables.
				 */
				foreach($_GET as $kget=>$vget):
					if(isset($_GET[$kget])):
					 	foreach($this->pat as $patron):
					 		preg_replace("/$patron/",$sus.$patron,$_GET[$kget]);
					 	endforeach;
					endif;
				endforeach;
				/*
				 * Reemplaza en el método POST 
				 * las variables vulnerables
				 */
				foreach($_POST as $kget=>$vget):
					if(isset($_POST[$kget])):
					 	foreach($this->pat as $patron):
					 		$_POST[$kget] = preg_replace("/$patron/",$sus.$patron,$_POST[$kget]);
					 	endforeach;
					endif;
				endforeach;
				break;
		endswitch;			
 	}
 }
?>
