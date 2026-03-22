package com.example.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/members")
public class MemberController {

    // Should be flagged — accepts email, no consent check
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        String email = request.getEmail();
        String name = request.getName();
        memberService.save(name, email);
        return ResponseEntity.ok().build();
    }

    // Should NOT be flagged — has consent check
    @PostMapping("/register-with-consent")
    public ResponseEntity<?> registerWithConsent(@RequestBody RegisterRequest request) {
        if (!request.isConsentGiven()) {
            return ResponseEntity.badRequest().build();
        }
        String email = request.getEmail();
        memberService.save(request.getName(), email);
        return ResponseEntity.ok().build();
    }

    // Should NOT be flagged — GET mapping, not POST/PUT
    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String query) {
        return ResponseEntity.ok(memberService.search(query));
    }

    // Should be flagged — PUT with phone, no 동의
    @PutMapping("/update")
    public ResponseEntity<?> update(@RequestBody UpdateRequest request) {
        String phone = request.getPhone();
        memberService.update(phone);
        return ResponseEntity.ok().build();
    }
}
