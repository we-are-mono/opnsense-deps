<?php

namespace OPNsense\Hwmon\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class SensorsController extends ApiControllerBase
{
    public function statusAction()
    {
        $backend = new Backend();
        $data = json_decode($backend->configdRun('hwmon sensors'), true);
        if (!is_array($data)) {
            return ['power' => [], 'fans' => [], 'temperatures' => []];
        }
        return $data;
    }
}
