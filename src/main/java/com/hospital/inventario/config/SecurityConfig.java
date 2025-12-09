http
    .csrf(csrf -> csrf.disable())
    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .authorizeHttpRequests(authz -> authz

        // ⚠️ Muy importante para preflight:
        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

        .requestMatchers("/auth/**", "/login", "/error").permitAll()
        .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
        .requestMatchers("/transacciones/api/**").permitAll()

        .requestMatchers("/configuracion/**")
            .hasAnyAuthority("ROLE_ADMIN", "ROLE_SUPERVISOR")

        .requestMatchers("/reportes/**")
            .hasAnyAuthority("ROLE_ADMIN", "ROLE_SUPERVISOR", "ROLE_OPERADOR")

        .requestMatchers("/productos/**", "/almacenes/**", "/inventario/**")
            .hasAnyAuthority("ROLE_ADMIN", "ROLE_SUPERVISOR", "ROLE_OPERADOR")

        .anyRequest().authenticated()
    )
    .authenticationProvider(authenticationProvider)
    .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
