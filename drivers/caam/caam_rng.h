/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * CAAM hardware entropy source — interface.
 */

#ifndef _CAAM_RNG_H
#define _CAAM_RNG_H

#include "caam_jr.h"

int	caam_rng_init(struct caam_jr_softc *jr);
void	caam_rng_detach(struct caam_jr_softc *jr);

#endif /* _CAAM_RNG_H */
