import { createI18n } from 'vue-i18n'
import zh from './locales/zh.json'
import en from './locales/en.json'

const messages = { zh, en }

// 读取 localStorage 或浏览器语言
const savedLang = localStorage.getItem('lang')
const browserLang = navigator.language.split('-')[0]
const locale = savedLang || (browserLang === 'zh' ? 'zh' : 'en')

const i18n = createI18n({
  legacy: false,         // 使用 Composition API
  locale,
  fallbackLocale: 'en',
  messages
})

export default i18n