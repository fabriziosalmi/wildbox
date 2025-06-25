'use client'

import * as React from "react"
import { ThemeProvider as NextThemesProvider, type ThemeProviderProps as NextThemeProviderProps } from "next-themes"

interface ThemeProviderProps {
  children: React.ReactNode
}

export function ThemeProvider({ children, ...props }: ThemeProviderProps & NextThemeProviderProps) {
  return <NextThemesProvider {...props}>{children}</NextThemesProvider>
}
