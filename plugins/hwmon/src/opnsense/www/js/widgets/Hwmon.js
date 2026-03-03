/*
 * Copyright (C) 2026 Mono Technologies d.o.o.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

export default class Hwmon extends BaseTableWidget {
    constructor() {
        super();
        this.tickTimeout = 10;
    }

    getGridOptions() {
        return {
            sizeToContent: 650
        };
    }

    getMarkup() {
        let $container = $('<div></div>');

        let $powerHeader = $(`<div class="hwmon-section" id="hwmon-power-section">
            <b><i class="fa fa-bolt"></i> ${this.translations.power}</b>
        </div>`);
        let $powerTable = this.createTable('hwmon-power', {
            headerPosition: 'left',
        });

        let $fanHeader = $(`<div class="hwmon-section" id="hwmon-fan-section">
            <b><i class="fa fa-fan"></i> ${this.translations.fans}</b>
        </div>`);
        let $fanTable = this.createTable('hwmon-fans', {
            headerPosition: 'left',
        });

        let $tempHeader = $(`<div class="hwmon-section" id="hwmon-temp-section">
            <b><i class="fa fa-thermometer-half"></i> ${this.translations.temperatures}</b>
        </div>`);
        let $tempTable = this.createTable('hwmon-temps', {
            headerPosition: 'left',
        });

        $container.append($powerHeader, $powerTable, $fanHeader, $fanTable, $tempHeader, $tempTable);
        return $container;
    }

    async onWidgetTick() {
        const data = await this.ajaxCall('/api/hwmon/sensors/status');

        if (!data || (!data.power?.length && !data.fans?.length && !data.temperatures?.length)) {
            $('#hwmon-power-section').hide();
            $('#hwmon-fan-section').hide();
            $('#hwmon-temp-section').hide();
            $('#hwmon-power').html(`<div style="margin: 1em;">${this.translations.nosensors}</div>`);
            return;
        }

        // Power sensors
        if (data.power?.length) {
            $('#hwmon-power-section').show();
            let powerRows = [];
            data.power.forEach(s => {
                let voltage = (s.voltage / 1000).toFixed(2);
                let current = (s.current / 1000).toFixed(2);
                powerRows.push([
                    s.label,
                    `${voltage} V &nbsp; ${current} A &nbsp; ${(s.power / 1000).toFixed(1)} W`
                ]);
            });
            super.updateTable('hwmon-power', powerRows);
        } else {
            $('#hwmon-power-section').hide();
        }

        // Fans
        if (data.fans?.length) {
            $('#hwmon-fan-section').show();
            let fanRows = [];
            data.fans.forEach(f => {
                let status = f.fault
                    ? '<i class="fa fa-exclamation-triangle text-danger"></i> Fault'
                    : `${f.rpm} RPM &nbsp; ${f.pwm}%`;
                fanRows.push([f.label, status]);
            });
            super.updateTable('hwmon-fans', fanRows);
        } else {
            $('#hwmon-fan-section').hide();
        }

        // Temperatures
        if (data.temperatures?.length) {
            $('#hwmon-temp-section').show();
            let tempRows = [];
            data.temperatures.forEach(t => {
                let color = t.value >= 80 ? 'text-danger' : (t.value >= 70 ? 'text-warning' : '');
                let display = color
                    ? `<span class="${color}">${t.value.toFixed(1)}&deg;C</span>`
                    : `${t.value.toFixed(1)}&deg;C`;
                tempRows.push([t.label, display]);
            });
            super.updateTable('hwmon-temps', tempRows);
        } else {
            $('#hwmon-temp-section').hide();
        }
    }
}
