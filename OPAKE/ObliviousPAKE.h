/*
 * ObliviousPAKE.h
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#ifndef OBLIVIOUSPAKE_H_
#define OBLIVIOUSPAKE_H_

#include "../PAKE/pake.h"
#include "../IHME/IHME.h"

#include <boost/shared_ptr.hpp>

class OPake {

protected:

	int c;
	std::vector<boost::shared_ptr<Pake> > procs;

public:
	virtual void init(std::vector<std::string>, ROLE, int) = 0;
	virtual mk next(message) = 0;

	virtual ~OPake(){}

};

#endif /* OBLIVIOUSPAKE_H_ */
