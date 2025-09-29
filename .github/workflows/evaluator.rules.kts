/*
 * Basic ORT Evaluator Rules
 *
 * This file contains basic rules for license compliance evaluation.
 * Rules are executed in order and the first matching rule determines the result.
 */

// Rule 1: Allow all permissive open source licenses
val rule1 = rule("Allow permissive licenses") {
    // Match packages with permissive licenses
    match { package ->
        package.declaredLicensesProcessed().values.any { license ->
            license in setOf(
                "MIT",
                "Apache-2.0",
                "BSD-2-Clause",
                "BSD-3-Clause",
                "ISC",
                "Unlicense"
            )
        }
    }

    // Set the status to allowed
    set { package ->
        package.setLicenseLicenseTo("ALLOWED")
    }
}

// Rule 2: Flag copyleft licenses for review
val rule2 = rule("Flag copyleft licenses for review") {
    // Match packages with copyleft licenses
    match { package ->
        package.declaredLicensesProcessed().values.any { license ->
            license in setOf(
                "GPL-2.0-only",
                "GPL-2.0-or-later",
                "GPL-3.0-only",
                "GPL-3.0-or-later",
                "LGPL-2.1-only",
                "LGPL-2.1-or-later",
                "LGPL-3.0-only",
                "LGPL-3.0-or-later",
                "MPL-2.0",
                "EPL-1.0",
                "EPL-2.0"
            )
        }
    }

    // Set the status to needs review
    set { package ->
        package.setLicenseLicenseTo("NEEDS_REVIEW")
        package.setMessage("Contains copyleft license - requires legal review")
    }
}

// Rule 3: Flag proprietary licenses as rejected
val rule3 = rule("Reject proprietary licenses") {
    // Match packages with proprietary licenses
    match { package ->
        package.declaredLicensesProcessed().values.any { license ->
            license in setOf(
                "Proprietary",
                "Commercial",
                "LicenseRef-proprietary"
            ) || license.contains("proprietary", ignoreCase = true)
        }
    }

    // Set the status to rejected
    set { package ->
        package.setLicenseLicenseTo("REJECTED")
        package.setMessage("Contains proprietary license - not allowed")
    }
}

// Rule 4: Flag unknown licenses for review
val rule4 = rule("Flag unknown licenses for review") {
    // Match packages with unknown licenses
    match { package ->
        package.declaredLicensesProcessed().values.any { license ->
            license in setOf("NOASSERTION") || license.startsWith("LicenseRef-unknown")
        }
    }

    // Set the status to needs review
    set { package ->
        package.setLicenseLicenseTo("NEEDS_REVIEW")
        package.setMessage("Contains unknown license - requires investigation")
    }
}

// Rule 5: Default rule - mark as needs review if no other rules match
val rule5 = rule("Default - needs review") {
    match { package -> true }

    set { package ->
        package.setLicenseLicenseTo("NEEDS_REVIEW")
        package.setMessage("No specific rule matched - manual review required")
    }
}