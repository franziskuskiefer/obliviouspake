/*
 * AdmissibleEncoding.h
 *
 *  Created on: Feb 7, 2013
 *      Author: franziskus
 */

#ifndef ADMISSIBLEENCODING_H_
#define ADMISSIBLEENCODING_H_

class AdmissibleEncoding {

private:

public:
	virtual Botan::BigInt encode(Botan::BigInt) = 0;
	virtual Botan::BigInt decode(Botan::BigInt) = 0;

	virtual ~AdmissibleEncoding(){
		// nothing here yet...
	}
};

#endif /* ADMISSIBLEENCODING_H_ */
