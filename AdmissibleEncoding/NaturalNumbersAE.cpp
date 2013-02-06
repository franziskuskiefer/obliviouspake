/*
 * NaturalNumbersAE.cpp
 *
 *  Created on: Feb 6, 2013
 *      Author: franziskus
 */

#include "NaturalNumbersAE.h"

// S -> R, i.e. T^l(sec) -> Z_n with |n|=sec and l ~ 2
NaturalNumbersAE::NaturalNumbersAE(Botan::BigInt n) {
	this->n = n;

	// have to define S, i.e.
	switch (this->n.bits()) {
	case 1024:
		this->ell = Botan::BigInt("32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853611059596231637");
		break;
	case 2048:
		this->ell = Botan::BigInt("1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225998300412344784862595674492194617023806505913245610825731835380087608622102834270197698202313169017678006675195485079921636419370285375124784014907159135459982790513399611551794271106831134090584272884279791554849782954323534517065223269061394905987693002122963395687782878948440616007412945674919823050571642377154816321380631045902916136926708342856440730447899971901781465763473223850267253059899795996090799469201774624817718449867455659250178329070473119433165550807568221846571746373296884912819520317457002440926616910874148385078411929804522981857338977648103126085903001302413467189726673216491511131602920781738033436090243804708340403154192097");
		break;
	case 3072:
		this->ell = Botan::BigInt("33751521821438561184911174488682640477482452690613543789987115108466500378467413241650309823759915214613546295086352135117206072620702805213786429827261190495295209725036214861444552245271001884442331336463841183659029156587178439044751051570054376203776342097110897640119327918012337424313355919359639652567871781286769270711026709157352924348777515574512579207430124960745017713811475633560361746240231372186987633281890003975124517410436232751786053258030904248989784343373580020429064399723981629210039686199812017059962040894145649613141899373457990136110124033082268445299759214270557020697837444729628470445553597383435232465858124331879290922696980222735667332393561216312300622989828829648566839376565747897273836250008772899562390160189852318683176499778475449534897302151083448535288367133592198444410244012903070619538476023121087011821602727130342062360292694196915030753475571047187621577677734015971061286266240776000199761459471444940463293093653202098729357658867135004032110599475307618336429187822239334863636668860337516076025023807524328879162142149805154128179503405390710994373783501948211730722860359837750090335272615847907847124069141199334722262055534377699054381370861337337471574548468743992660475775028572280267994135704993835355977695442635432946193561821017089736627379071131483930684532622952398897715491344942216169944540811346628089421863683937920456996873353908785220590722518585909106605811532117238941679346587984132366957891357781759795220034581173473479726235700321529495539776440692644558284469348870671055995987203062730525276396026962916718358629845520556495152513597870927982785774674929765072485149682462794408926127267616060623923370839359058434846610501532154221129624066335698266050975882792155955005954460099419877138745992453542401993667168494168245722096801075794308992327588609520244453197182140791");
		break;
	case 4096:
		this->ell = Botan::BigInt("1090748135619415929462984244733782862448264161996232692431832786189721331849119295216264234525201987223957291796157025273109870820177184063610979765077554799078906298842192989538609825228048205159696851613591638196771886542609324560121290553901886301017900252535799917200010079600026535836800905297805880952350501630195475653911005312364560014847426035293551245843928918752768696279344088055617515694349945406677825140814900616105920256438504578013326493565836047242407382442812245131517757519164899226365743722432277368075027627883045206501792761700945699168497257879683851737049996900961120515655050115561271491492515342105748966629547032786321505730828430221664970324396138635251626409516168005427623435996308921691446181187406395310665404885739434832877428167407495370993511868756359970390117021823616749458620969857006263612082706715408157066575137281027022310927564910276759160520878304632411049364568754920967322982459184763427383790272448438018526977764941072715611580434690827459339991961414242741410599117426060556483763756314527611362658628383368621157993638020878537675545336789915694234433955666315070087213535470255670312004130725495834508357439653828936077080978550578912967907352780054935621561090795845172954115972927479877527738560008204118558930004777748727761853813510493840581861598652211605960308356405941821189714037868726219481498727603653616298856174822413033485438785324024751419417183012281078209729303537372804574372095228703622776363945290869806258422355148507571039619387449629866808188769662815778153079393179093143648340761738581819563002994422790754955061288818308430079648693232179158765918035565216157115402992120276155607873107937477466841528362987708699450152031231862594203085693838944657061346236704234026821102958954951197087076546186622796294536451620756509351018906023773821539532776208676978589731966330308893304665169436185078350641568336944530051437491311298834367265238595404904273455928723949525227184617404367854754610474377019768025576605881038077270707717942221977090385438585844095492116099852538903974655703943973086090930596963360767529964938414598185705963754561497355827813623833288906309004288017321424808663962671333528009232758350873059614118723781422101460198615747386855096896089189180441339558524822867541113212638793675567650340362970031930023397828465318547238244232028015189689660418822976000815437610652254270163595650875433851147123214227266605403581781469090806576468950587661997186505665475715793793");
		break;
		//			case 6144:
		//				two22l = Botan::BigInt();
		//				break;
		//			case 8192:
		//				two22l = Botan::BigInt();
		//				break;
	default:
		std::cout << "----- ERROR (NaturalNumbersAE::encode - N has strange bit size -----\n";
		exit(1);
		break;
	}
}

Botan::BigInt NaturalNumbersAE::encode(Botan::BigInt in) {
	Botan::AutoSeeded_RNG rng;

	if (in.bits() <= this->n.bits()){
		this->k = Botan::BigInt::random_integer(rng, Botan::BigInt(0), this->ell/this->n-1); // XXX: ceil?
		return in + this->k*this->n;
	} else {
		std::cout << "----- ERROR (NaturalNumbersAE::encode not possible - in.size=" << in.bits() << " - n.size=" << this->n.bits() << ")\n";
		return Botan::BigInt(0);
	}
}

Botan::BigInt NaturalNumbersAE::decode(Botan::BigInt in) {
	return in % this->n;
}
