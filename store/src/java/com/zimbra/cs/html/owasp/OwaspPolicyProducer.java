package com.zimbra.cs.html.owasp;

/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2019 Synacor, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
import java.util.List;
import java.util.Set;

import org.owasp.html.CssSchema;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import com.google.common.collect.ImmutableSet;

public class OwaspPolicyProducer {

    private HtmlElementsBuilder builder;
    private boolean neuterImages;
    private PolicyFactory policy;

    /**
     * The following CSS properties do not appear in the default whitelist from
     * OWASP, but they improve the fidelity of the HTML display without
     * unacceptable risk.
     */
    private static final CssSchema ADDITIONAL_CSS = CssSchema
        .withProperties(ImmutableSet.of("float"));

    public OwaspPolicyProducer(HtmlElementsBuilder builder, boolean neuterImages) {
        this.builder = builder;
        this.neuterImages = neuterImages;
        setUp();
    }

    private void setUp() {
        List<HtmlElement> allowedElements = builder.build();
        HtmlPolicyBuilder policyBuilder = new HtmlPolicyBuilder();
        for (HtmlElement htmlElement : allowedElements) {
            htmlElement.configure(policyBuilder, neuterImages);
        }
        Set<String> disallowTextElements = OwaspPolicy.getDisallowTextElements();
        for (String disAllowTextElement : disallowTextElements) {
            policyBuilder.disallowTextIn(disAllowTextElement.trim());
        }
        Set<String> urlProtocols = OwaspPolicy.getURLProtocols();
        for (String urlProtocol : urlProtocols) {
            policyBuilder.allowUrlProtocols(urlProtocol.trim());
        }
        policy = policyBuilder.allowStyling(CssSchema.union(CssSchema.DEFAULT, ADDITIONAL_CSS))
            .toFactory();
    }

    public PolicyFactory getPolicyFactoryInstance() {
        return policy;
    }
}